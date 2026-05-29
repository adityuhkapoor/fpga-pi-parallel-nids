`timescale 1ns/1ps
// NIDS pipeline top: spi_slave_rx -> header_parser -> { classifiers (v1.1) ‖ telemetry (v2) },
// response shifted back on MISO one frame later (PROTOCOL.md). Request byte 16 is the opcode:
//   0x00 classify        -> verdict frame (magic 0xA5), v1.1 path
//   0x01 cms point-query -> {0x5A, key:32, count:14}
//   0x02 window snapshot -> {0x5A, window, total, sum, zeros, top1_count, top1_key}
//   0x03 hll harmonic    -> {0x5A, harmonic_sum, zeros, m}
// Telemetry counts every 0x00 frame's src_ip; classifier state is gated to 0x00 only so query
// frames never perturb scan_rate. seq is still K&0xFF for the K-th received frame.
module nids_top (
    input  wire        clk,    // 100 MHz
    input  wire        btnC,   // reset
    input  wire        sclk,
    input  wire        cs_n,
    input  wire        mosi,
    output wire        miso,
    output wire [15:0] led
);
    localparam FRAME_BYTES = 32;
    localparam FRAME_BITS  = FRAME_BYTES*8;

    wire rst = btnC;

    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    // --- opcode decode (byte 16 of the request) + per-frame in-flight latch ---
    wire [7:0] opcode = rx_frame[FRAME_BITS-1-128 -: 8];
    reg  [7:0] inflight_op;
    always @(posedge clk) if (rx_frame_valid) inflight_op <= opcode;

    // --- per-frame counter (drives seq for classify verdicts) ---
    reg [15:0] frame_count;
    reg [15:0] frame_idx;
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

    // --- header parse (runs regardless of opcode; src_ip = bytes 0-3 doubles as query key) ---
    wire [31:0] src_ip, dst_ip;
    wire [15:0] src_port, dst_port, pkt_size;
    wire [7:0]  proto, tcp_flags;
    wire        fields_valid;
    header_parser #(.FRAME_BYTES(FRAME_BYTES)) u_parser (
        .clk(clk), .rst(rst), .frame(rx_frame), .frame_valid(rx_frame_valid),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size), .fields_valid(fields_valid)
    );

    // gate by latched opcode so query frames don't perturb classifier state or telemetry counts
    wire classify_now = fields_valid && (inflight_op == 8'h00);
    wire cms_q_now    = fields_valid && (inflight_op == 8'h01);

    // --- v1.1 classifier path (unchanged behavior, just gated by classify_now) ---
    wire [2:0] hit_mask;
    wire [1:0] severity;
    wire       escalate, classify_valid;
    classifiers u_cls (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size),
        .frame_count(frame_idx), .fields_valid(classify_now),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .classify_valid(classify_valid)
    );

    wire [FRAME_BITS-1:0] verdict_frame;
    wire                  verdict_valid;
    verdict_encoder #(.FRAME_BYTES(FRAME_BYTES)) u_venc (
        .clk(clk), .rst(rst), .classify_valid(classify_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .seq(seq_reg),
        .verdict_frame(verdict_frame), .verdict_valid(verdict_valid)
    );

    // --- v2 telemetry: 1 s window (100M cycles @100MHz); count classify frames' src_ip ---
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

    // latch the CMS-query key so the response holds it stably (the count comes from cms_count
    // directly — using a separate latched q_count_reg races: both q_count_reg <= cms_count and
    // tx_reg <= {..., q_count_reg, ...} fire same edge T, so tx_reg would read the OLD value).
    reg [31:0] q_key_reg;
    always @(posedge clk) if (cms_q_now) q_key_reg <= src_ip;

    // --- response mux: load tx_reg with the correct response for the in-flight frame ---
    reg [FRAME_BITS-1:0] tx_reg;
    always @(posedge clk) begin
        if (rst) tx_reg <= {FRAME_BITS{1'b0}};
        else case (inflight_op)
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
    end

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(tx_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );
endmodule
