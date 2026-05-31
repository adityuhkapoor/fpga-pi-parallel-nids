`timescale 1ns/1ps
// NIDS pipeline top: spi_slave_rx -> header_parser -> { classifiers (v1.1) || telemetry (v2 step 1) },
// response shifted back on MISO one frame later (PROTOCOL.md). Request byte 16 = opcode.
//   0x00 classify        -> verdict (magic 0xA5), v1.1 path
//   0x01 cms point-query -> {0x5A, key, count}
//   0x02 window snapshot -> {0x5A, window, total, sum, zeros, top1_count, top1_key}
//   0x03 hll harmonic    -> {0x5A, harmonic_sum, zeros, m}
//   0x10 bloom write     -> {0x5A, 0x10}                          (step 2)
//   0x11 threshold write -> {0x5A, 0x11}
//   0x12 rule write      -> {0x5A, 0x12}
//   0x13 bloom read      -> {0x5A, addr_echo, value}
//   0x14 threshold read  -> {0x5A, id_echo, value}
//   0x15 rule read       -> {0x5A, idx_echo, rule:9 bytes}
// Telemetry counts every 0x00 frame's src_ip; classifier state is gated to 0x00 only so query
// and control frames never perturb scan_rate. step-2 control opcodes (0x10-0x15) drive the
// thresholds reg-file, rule_store BRAM, and the bloom port-B write/readback path.
module nids_top (
    input  wire        clk,
    input  wire        btnC,
    input  wire        sclk, cs_n, mosi,
    output wire        miso,
    output wire [15:0] led
);
    localparam FRAME_BYTES = 32;
    localparam FRAME_BITS  = FRAME_BYTES*8;
    wire rst = btnC;

    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    // opcode + per-frame latches
    wire [7:0] opcode = rx_frame[FRAME_BITS-1-128 -: 8];
    reg  [7:0] inflight_op;
    always @(posedge clk) if (rx_frame_valid) inflight_op <= opcode;

    reg [15:0] frame_count, frame_idx;
    reg [7:0]  seq_reg;
    always @(posedge clk) begin
        if (rst) begin frame_count<=16'd0; frame_idx<=16'd0; seq_reg<=8'd0; end
        else if (rx_frame_valid) begin
            frame_idx   <= frame_count;
            frame_count <= frame_count + 16'd1;
            seq_reg     <= frame_count[7:0] + 8'd1;
        end
    end
    assign led = frame_count;

    // header parse (runs regardless of opcode)
    wire [31:0] src_ip, dst_ip;
    wire [15:0] src_port, dst_port, pkt_size;
    wire [7:0]  proto, tcp_flags;
    wire        fields_valid;
    header_parser #(.FRAME_BYTES(FRAME_BYTES)) u_parser (
        .clk(clk), .rst(rst), .frame(rx_frame), .frame_valid(rx_frame_valid),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size), .fields_valid(fields_valid)
    );

    wire classify_now = fields_valid && (inflight_op == 8'h00);
    wire cms_q_now    = fields_valid && (inflight_op == 8'h01);
    wire ctrl_now     = fields_valid && (inflight_op[7:4] == 4'h1);   // any 0x1X

    // --- step-2 control: extract raw fields from rx_frame (byte addresses per PROTOCOL.md) ---
    wire [15:0] op_b0_1 = rx_frame[FRAME_BITS-1  -: 16];     // bytes 0-1
    wire [15:0] op_b2_3 = rx_frame[FRAME_BITS-17 -: 16];     // bytes 2-3
    wire [71:0] op_b2_10= rx_frame[FRAME_BITS-17 -: 72];     // bytes 2-10 (72-bit rule)
    wire [7:0]  op_b0   = rx_frame[FRAME_BITS-1  -: 8];      // byte 0
    wire [15:0] op_b1_2 = rx_frame[FRAME_BITS-9  -: 16];     // bytes 1-2

    // thresholds reg-file (writes on 0x11, reads on 0x14; live taps fed to classifiers).
    // v2 step 4: also exposes a `rule_epoch` tap (id 0x03) consumed by rule_lookup.
    wire [15:0] port_thresh, host_thresh, rate_thresh;
    wire [7:0]  current_rule_epoch;
    wire [15:0] thr_r_val;
    thresholds u_thr (
        .clk(clk), .rst(rst),
        .w_id(op_b0), .w_val(op_b1_2), .w_en(fields_valid && (inflight_op == 8'h11)),
        .r_id(op_b0), .r_val(thr_r_val),
        .port_thresh(port_thresh), .host_thresh(host_thresh), .rate_thresh(rate_thresh),
        .rule_epoch(current_rule_epoch)
    );

    // rule_store: r_idx is muxed between Pi readback (opcode 0x15) and the per-packet
    // classifier rule_lookup (combinational hash of src_ip). The two never overlap because
    // 0x15 frames don't go through classify_now.
    wire [8:0]  classifier_rs_r_idx;
    wire [8:0]  rs_r_idx_mux = (inflight_op == 8'h15) ? op_b0_1[8:0] : classifier_rs_r_idx;
    wire [71:0] rule_r_rule;
    rule_store u_rs (
        .clk(clk),
        .w_idx(op_b0_1[8:0]), .w_rule(op_b2_10),
        .w_en(fields_valid && (inflight_op == 8'h12)),
        .r_idx(rs_r_idx_mux), .r_rule(rule_r_rule)
    );

    // bloom port-B signals (the bloom is inside classifiers; we thread these through)
    wire [11:0] bf_w_addr = op_b0_1[11:0];
    wire [15:0] bf_w_data = op_b2_3;
    wire        bf_w_en   = fields_valid && (inflight_op == 8'h10);
    wire [11:0] bf_r_addr = op_b0_1[11:0];
    wire        bf_r_en   = fields_valid && (inflight_op == 8'h13);
    wire [15:0] bf_r_data;

    // v1.1+v2 classifier path (gated to opcode 0x00). Now includes flow_table (step 3,
    // replaces scan_rate) and rule_lookup (step 4, reads rule_store at src_ip's hash).
    wire [3:0] hit_mask;
    wire [1:0] severity;
    wire       escalate, classify_valid;
    classifiers u_cls (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size),
        .frame_count(frame_idx), .fields_valid(classify_now),
        .port_thresh(port_thresh), .host_thresh(host_thresh), .rate_thresh(rate_thresh),
        .bf_w_addr(bf_w_addr), .bf_w_data(bf_w_data), .bf_w_en(bf_w_en),
        .bf_r_addr(bf_r_addr), .bf_r_en(bf_r_en),   .bf_r_data(bf_r_data),
        .current_rule_epoch(current_rule_epoch),
        .rs_r_idx(classifier_rs_r_idx), .rs_r_rule(rule_r_rule),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .classify_valid(classify_valid)
    );

    wire [FRAME_BITS-1:0] verdict_frame;
    wire                  verdict_valid;
    verdict_encoder #(.FRAME_BYTES(FRAME_BYTES)) u_venc (
        .clk(clk), .rst(rst), .classify_valid(classify_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .seq(seq_reg),
        .verdict_frame(verdict_frame), .verdict_valid(verdict_valid)
    );

    // v2 step-1 telemetry (unchanged)
    wire [13:0] cms_count;  wire cms_done;
    wire [47:0] live_harmonic_sum;  wire [11:0] live_zeros;
    wire [15:0] snap_window;        wire [31:0] snap_total;
    wire [47:0] snap_harmonic_sum;  wire [11:0] snap_zeros;
    wire [13:0] snap_top1_count;    wire [31:0] snap_top1_key;
    telemetry u_tel (
        .clk(clk), .rst(rst), .src_ip(src_ip),
        .upd_valid(classify_now), .force_tick(1'b0),
        .q_ip(src_ip), .q_valid(cms_q_now), .q_count(cms_count), .q_done(cms_done),
        .live_harmonic_sum(live_harmonic_sum), .live_zeros(live_zeros),
        .snap_window(snap_window), .snap_total(snap_total),
        .snap_harmonic_sum(snap_harmonic_sum), .snap_zeros(snap_zeros),
        .snap_top1_count(snap_top1_count), .snap_top1_key(snap_top1_key)
    );

    reg [31:0] q_key_reg;
    always @(posedge clk) if (cms_q_now) q_key_reg <= src_ip;

    // control-opcode ack/response pipeline: 2-cycle delay from fields_valid so registered
    // BRAM/reg reads (bf_r_data, thr_r_val, rule_r_rule) are stable when tx_reg captures them.
    reg ctrl_pipe1, ctrl_pipe2;
    reg [7:0]  ctrl_op_lat;
    reg [15:0] ctrl_b0_1_lat;
    reg [7:0]  ctrl_b0_lat;
    always @(posedge clk) begin
        ctrl_pipe1 <= ctrl_now;
        ctrl_pipe2 <= ctrl_pipe1;
        if (ctrl_now) begin
            ctrl_op_lat   <= inflight_op;
            ctrl_b0_1_lat <= op_b0_1;
            ctrl_b0_lat   <= op_b0;
        end
    end

    // response mux
    reg [FRAME_BITS-1:0] tx_reg;
    always @(posedge clk) begin
        if (rst) tx_reg <= {FRAME_BITS{1'b0}};
        else begin
            // step-1 cases (verdict + telemetry responses) — unchanged behavior
            case (inflight_op)
                8'h00: if (verdict_valid) tx_reg <= verdict_frame;
                8'h01: if (cms_done)
                    tx_reg <= {8'h5A, q_key_reg, {2'b0, cms_count}, 200'd0};
                8'h02: if (fields_valid)
                    tx_reg <= {8'h5A, snap_window, snap_total, snap_harmonic_sum,
                               {4'b0, snap_zeros}, {2'b0, snap_top1_count}, snap_top1_key, 88'd0};
                8'h03: if (fields_valid)
                    tx_reg <= {8'h5A, live_harmonic_sum, {4'b0, live_zeros}, 16'd2048, 168'd0};
                default: ;
            endcase
            // step-2 control responses — load 2 cycles after fields_valid so reads are settled
            if (ctrl_pipe2) case (ctrl_op_lat)
                8'h10: tx_reg <= {8'h5A, 8'h10, 240'd0};
                8'h11: tx_reg <= {8'h5A, 8'h11, 240'd0};
                8'h12: tx_reg <= {8'h5A, 8'h12, 240'd0};
                8'h13: tx_reg <= {8'h5A, ctrl_b0_1_lat, bf_r_data,                  216'd0};
                8'h14: tx_reg <= {8'h5A, ctrl_b0_lat,   thr_r_val,                  224'd0};
                8'h15: tx_reg <= {8'h5A, ctrl_b0_1_lat, rule_r_rule,                160'd0};
                default: ;
            endcase
        end
    end

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(tx_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );
endmodule
