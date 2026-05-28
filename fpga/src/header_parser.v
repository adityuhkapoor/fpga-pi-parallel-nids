`timescale 1ns/1ps
// Splits the header frame into fields. Layout is the fixed big-endian contract
// (PROTOCOL.md); byte 0 is the top byte (frame[FRAME_BITS-1 -: 8]) so the slices are
// width-agnostic. Latches on frame_valid and pulses fields_valid the same cycle.
module header_parser #(
    parameter FRAME_BYTES = 32
)(
    input  wire                     clk,
    input  wire                     rst,
    input  wire [FRAME_BYTES*8-1:0] frame,
    input  wire                     frame_valid,
    output reg  [31:0]              src_ip,
    output reg  [31:0]              dst_ip,
    output reg  [15:0]              src_port,
    output reg  [15:0]              dst_port,
    output reg  [7:0]               proto,
    output reg  [7:0]               tcp_flags,
    output reg  [15:0]              pkt_size,
    output reg                      fields_valid
);
    localparam FRAME_BITS = FRAME_BYTES*8;
    always @(posedge clk) begin
        fields_valid <= 1'b0;
        if (rst) begin
            fields_valid <= 1'b0;
        end else if (frame_valid) begin
            src_ip       <= frame[FRAME_BITS-1   -: 32];   // bytes 0-3
            dst_ip       <= frame[FRAME_BITS-33  -: 32];   // bytes 4-7
            src_port     <= frame[FRAME_BITS-65  -: 16];   // bytes 8-9
            dst_port     <= frame[FRAME_BITS-81  -: 16];   // bytes 10-11
            proto        <= frame[FRAME_BITS-97  -:  8];   // byte 12
            tcp_flags    <= frame[FRAME_BITS-105 -:  8];   // byte 13
            pkt_size     <= frame[FRAME_BITS-113 -: 16];   // bytes 14-15
            fields_valid <= 1'b1;                          // bytes 16+ (reserved) dropped
        end
    end
endmodule
