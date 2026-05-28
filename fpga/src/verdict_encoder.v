`timescale 1ns/1ps
// Packs a classification result into the 20-byte verdict frame (PROTOCOL.md Response).
// Byte 0 magic, 1 stage-hit mask, 2 severity, 3 flags, 4 seq, 5-19 reserved.
// magic is 0xA5 only for a real verdict; the register powers up / resets to all-zero,
// so the first transfer (and any post-reset transfer) carries magic=0x00 = "no verdict".
module verdict_encoder #(
    parameter FRAME_BYTES = 32
)(
    input  wire                     clk,
    input  wire                     rst,
    input  wire                     classify_valid,
    input  wire [2:0]               hit_mask,   // bit0 bloom, bit1 port-scan, bit2 rate
    input  wire [1:0]               severity,
    input  wire                     escalate,
    input  wire [7:0]               seq,
    output reg  [FRAME_BYTES*8-1:0] verdict_frame,
    output reg                      verdict_valid
);
    localparam RSVD = (FRAME_BYTES-5)*8;   // reserved bytes 5..19

    always @(posedge clk) begin
        verdict_valid <= 1'b0;
        if (rst) begin
            verdict_frame <= {FRAME_BYTES*8{1'b0}};
            verdict_valid <= 1'b0;
        end else if (classify_valid) begin
            verdict_frame <= {8'hA5, {5'b0, hit_mask}, {6'b0, severity},
                              {7'b0, escalate}, seq, {RSVD{1'b0}}};
            verdict_valid <= 1'b1;
        end
    end
endmodule
