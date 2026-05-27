`timescale 1ns/1ps
// Bloom membership for the C2-IP match (CLASSIFIER.md). m=65536-bit array held as
// 4096x16-bit BRAM (bloom_init.mem); k=2 multiply-shift hashes per IP. A query checks
// src_ip then dst_ip: bloom_hit = member(src) | member(dst).
//
// member(ip) needs both bits bit[h1] and bit[h2]; the two reads share a dual-port ROM.
// Synchronous reads have a one-cycle latency, so a query walks four phases:
//   0  latch indices, issue src read pair
//   1  issue dst read pair (src data lands at this edge)
//   2  capture member(src); dst data lands at this edge
//   3  combine with member(dst), pulse out_valid
// At 100 MHz this is ~40 ns, far inside the >150 us SPI frame period.
module bloom_filter #(
    parameter MEM_FILE = "bloom_init.mem"
)(
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire        in_valid,
    output reg         bloom_hit,
    output reg         out_valid
);
    localparam [31:0] A1 = 32'h9E3779B1;
    localparam [31:0] A2 = 32'h85EBCA77;

    // index = (ip * A) low-32 bits, then [31:16]
    function [15:0] bidx(input [31:0] ip, input [31:0] a);
        reg [63:0] prod;
        begin
            prod = {32'd0, ip} * a;
            bidx = prod[31:16];
        end
    endfunction

    (* ram_style = "block" *) reg [15:0] mem [0:4095];
    initial $readmemh(MEM_FILE, mem);

    reg [11:0] addr_a, addr_b;
    reg [15:0] rdata_a, rdata_b;
    always @(posedge clk) begin
        rdata_a <= mem[addr_a];
        rdata_b <= mem[addr_b];
    end

    wire [15:0] idx_h1s = bidx(src_ip, A1);
    wire [15:0] idx_h2s = bidx(src_ip, A2);
    wire [15:0] idx_h1d = bidx(dst_ip, A1);
    wire [15:0] idx_h2d = bidx(dst_ip, A2);

    reg [15:0] h1s, h2s, h1d, h2d;   // latched indices (bit-select survives both reads)
    reg [1:0]  phase;
    reg        member_src;

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            phase     <= 2'd0;
            bloom_hit <= 1'b0;
        end else case (phase)
            2'd0: if (in_valid) begin
                      h1s <= idx_h1s; h2s <= idx_h2s;
                      h1d <= idx_h1d; h2d <= idx_h2d;
                      addr_a <= idx_h1s[15:4];   // src read pair
                      addr_b <= idx_h2s[15:4];
                      phase  <= 2'd1;
                  end
            2'd1: begin
                      addr_a <= h1d[15:4];       // dst read pair
                      addr_b <= h2d[15:4];
                      phase  <= 2'd2;
                  end
            2'd2: begin
                      member_src <= rdata_a[h1s[3:0]] & rdata_b[h2s[3:0]];
                      phase      <= 2'd3;
                  end
            2'd3: begin
                      bloom_hit <= member_src | (rdata_a[h1d[3:0]] & rdata_b[h2d[3:0]]);
                      out_valid <= 1'b1;
                      phase     <= 2'd0;
                  end
        endcase
    end
endmodule
