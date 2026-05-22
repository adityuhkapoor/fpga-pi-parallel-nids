`timescale 1ns/1ps
// Splits the 20-byte header frame into fields. Layout is the fixed big-endian
// contract (PROTOCOL.md); frame[159:152] is byte 0. Latches on frame_valid and
// pulses fields_valid the same cycle.
module header_parser #(
    parameter FRAME_BYTES = 20
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
    always @(posedge clk) begin
        fields_valid <= 1'b0;
        if (rst) begin
            fields_valid <= 1'b0;
        end else if (frame_valid) begin
            src_ip       <= frame[159:128];   // bytes 0-3
            dst_ip       <= frame[127:96];    // bytes 4-7
            src_port     <= frame[95:80];     // bytes 8-9
            dst_port     <= frame[79:64];     // bytes 10-11
            proto        <= frame[63:56];     // byte 12
            tcp_flags    <= frame[55:48];     // byte 13
            pkt_size     <= frame[47:32];     // bytes 14-15
            fields_valid <= 1'b1;             // bytes 16-19 (reserved) dropped
        end
    end
endmodule
