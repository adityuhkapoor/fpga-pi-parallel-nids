`timescale 1ns/1ps
// Parallel classifier block: bloom (C2-IP, stateless) + scan_rate (port-scan + rate-anomaly,
// stateful). Both start on fields_valid and finish a few cycles later with independent
// latencies; classify_valid pulses once BOTH have produced their result for the packet.
// hit_mask = {rate, port_scan, bloom}; severity = max of fired stages (bloom 3, scan/rate 2);
// escalate = any stage fired. frame_count is the 0-based packet index (drives the window epoch).
module classifiers (
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] src_port,
    input  wire [15:0] dst_port,
    input  wire [7:0]  proto,
    input  wire [7:0]  tcp_flags,
    input  wire [15:0] pkt_size,
    input  wire [15:0] frame_count,
    input  wire        fields_valid,
    // v2 step-2 passthroughs (driven by nids_top from the opcode router / thresholds reg file)
    input  wire [15:0] port_thresh, host_thresh, rate_thresh,    // scan_rate runtime thresholds
    input  wire [11:0] bf_w_addr, bf_r_addr,                     // bloom port-B
    input  wire [15:0] bf_w_data,
    input  wire        bf_w_en, bf_r_en,
    output wire [15:0] bf_r_data,
    output reg  [2:0]  hit_mask,        // bit0 bloom, bit1 port-scan, bit2 rate
    output reg  [1:0]  severity,
    output reg         escalate,
    output reg         classify_valid
);
    wire bloom_hit, bloom_valid;
    bloom_filter u_bloom (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .in_valid(fields_valid), .bloom_hit(bloom_hit), .out_valid(bloom_valid),
        .w_addr(bf_w_addr), .w_data(bf_w_data), .w_en(bf_w_en),
        .r_addr(bf_r_addr), .r_en(bf_r_en),   .r_data(bf_r_data)
    );

    wire ps_hit, rate_hit, sr_valid;
    scan_rate u_sr (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .dst_port(dst_port), .proto(proto), .tcp_flags(tcp_flags),
        .frame_count(frame_count), .in_valid(fields_valid),
        .port_thresh(port_thresh), .host_thresh(host_thresh), .rate_thresh(rate_thresh),
        .port_scan_hit(ps_hit), .rate_hit(rate_hit), .out_valid(sr_valid)
    );

    // The two stages have independent latencies. Latch each result as it lands; emit the
    // combined verdict once both are in. Frames are >150us apart vs a few-cycle pipeline,
    // so a new packet never overlaps the previous one's stages.
    reg bloom_done, sr_done;
    reg bh_l, ps_l, rate_l;
    always @(posedge clk) begin
        classify_valid <= 1'b0;
        if (rst) begin
            bloom_done <= 1'b0; sr_done <= 1'b0;
            hit_mask <= 3'd0; severity <= 2'd0; escalate <= 1'b0;
        end else begin
            if (fields_valid) begin bloom_done <= 1'b0; sr_done <= 1'b0; end
            if (bloom_valid)  begin bloom_done <= 1'b1; bh_l   <= bloom_hit;            end
            if (sr_valid)     begin sr_done   <= 1'b1; ps_l   <= ps_hit; rate_l <= rate_hit; end
            if (bloom_done && sr_done) begin
                hit_mask       <= {rate_l, ps_l, bh_l};
                severity       <= bh_l ? 2'd3 : ((ps_l | rate_l) ? 2'd2 : 2'd0);
                escalate       <= bh_l | ps_l | rate_l;
                classify_valid <= 1'b1;
                bloom_done     <= 1'b0;
                sr_done        <= 1'b0;
            end
        end
    end
endmodule
