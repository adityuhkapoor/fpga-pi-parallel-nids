`timescale 1ns/1ps
// Bloom membership for the C2-IP match (CLASSIFIER.md). m=65536-bit array held as
// 4096x16-bit BRAM (bloom_init.mem at boot, runtime-rewritable via opcode 0x10); k=2
// multiply-shift hashes per IP. A query checks src_ip then dst_ip: bloom_hit = member(src)
// | member(dst), and member(ip) = bit[h1] & bit[h2]. For v2: port A handles the 4 query
// reads serially (h1s, h2s, h1d, h2d -> 6-phase FSM); port B is dedicated to the Pi
// (write on w_en, readback on r_en). One RAMB36 total, no duplication. Frame period at
// 8 MHz (32 us) dwarfs the 6-cycle query (60 ns @100 MHz).
module bloom_filter #(
    parameter MEM_FILE = "bloom_init.mem"
)(
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire        in_valid,
    output reg         bloom_hit,
    output reg         out_valid,
    // step-2 port B: Pi writes (opcode 0x10) and Pi readback (opcode 0x13). Mutually exclusive.
    input  wire [11:0] w_addr,
    input  wire [15:0] w_data,
    input  wire        w_en,
    input  wire [11:0] r_addr,
    input  wire        r_en,
    output reg  [15:0] r_data
);
    localparam [31:0] A1 = 32'h9E3779B1;
    localparam [31:0] A2 = 32'h85EBCA77;

    function [15:0] bidx(input [31:0] ip, input [31:0] a);
        reg [63:0] prod;
        begin
            prod = {32'd0, ip} * a;
            bidx = prod[31:16];
        end
    endfunction

    (* ram_style = "block" *) reg [15:0] mem [0:4095];
    initial $readmemh(MEM_FILE, mem);

    // Port A: classifier read (one address per cycle, 1-cycle synchronous read latency)
    reg [11:0] addr_a;
    reg [15:0] rdata_a;
    always @(posedge clk) rdata_a <= mem[addr_a];

    // Port B: Pi write OR Pi readback (mutex; Pi never asserts both same cycle)
    initial r_data = 16'd0;
    always @(posedge clk) begin
        if (w_en)      mem[w_addr] <= w_data;
        else if (r_en) r_data      <= mem[r_addr];
    end

    wire [15:0] idx_h1s = bidx(src_ip, A1);
    wire [15:0] idx_h2s = bidx(src_ip, A2);
    wire [15:0] idx_h1d = bidx(dst_ip, A1);
    wire [15:0] idx_h2d = bidx(dst_ip, A2);

    reg [15:0] h1s, h2s, h1d, h2d;
    reg [15:0] h1s_word, h2s_word, h1d_word;
    reg [2:0]  phase;

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            phase     <= 3'd0;
            bloom_hit <= 1'b0;
        end else case (phase)
            3'd0: if (in_valid) begin
                      h1s <= idx_h1s; h2s <= idx_h2s; h1d <= idx_h1d; h2d <= idx_h2d;
                      addr_a <= idx_h1s[15:4];
                      phase  <= 3'd1;
                  end
            3'd1: begin addr_a <= h2s[15:4];                          phase <= 3'd2; end
            3'd2: begin h1s_word <= rdata_a;  addr_a <= h1d[15:4];    phase <= 3'd3; end
            3'd3: begin h2s_word <= rdata_a;  addr_a <= h2d[15:4];    phase <= 3'd4; end
            3'd4: begin h1d_word <= rdata_a;                          phase <= 3'd5; end
            3'd5: begin
                      bloom_hit <= (h1s_word[h1s[3:0]] & h2s_word[h2s[3:0]])
                                 | (h1d_word[h1d[3:0]] & rdata_a [h2d[3:0]]);
                      out_valid <= 1'b1;
                      phase     <= 3'd0;
                  end
            default: phase <= 3'd0;
        endcase
    end
endmodule
