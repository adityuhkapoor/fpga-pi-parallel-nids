`timescale 1ns/1ps
// Parallel classifier block: bloom (C2-IP), port-scan, rate-anomaly.
// v1 = bloom only (CLASSIFIER.md): mask bit0 = bloom_hit -> severity 3, escalate.
// Port-scan (bit1) and rate-anomaly (bit2) are stateful and stay stubbed 0 until v1.1.
// classify_valid tracks the bloom result valid (a few cycles after fields_valid).
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
    input  wire        fields_valid,
    output reg  [2:0]  hit_mask,        // bit0 bloom, bit1 port-scan, bit2 rate
    output reg  [1:0]  severity,
    output reg         escalate,
    output reg         classify_valid
);
    wire bloom_hit, bloom_valid;

    bloom_filter u_bloom (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .in_valid(fields_valid),
        .bloom_hit(bloom_hit), .out_valid(bloom_valid)
    );

    always @(posedge clk) begin
        classify_valid <= 1'b0;
        if (rst) begin
            hit_mask <= 3'b000; severity <= 2'd0; escalate <= 1'b0;
        end else if (bloom_valid) begin
            hit_mask       <= {2'b00, bloom_hit};       // bits 2:1 deferred to v1.1
            severity       <= bloom_hit ? 2'd3 : 2'd0;
            escalate       <= bloom_hit;
            classify_valid <= 1'b1;
        end
    end
endmodule
