`timescale 1ns/1ps
// Runtime rule store: 512 x 72-bit rules indexed 0..511 (PROTOCOL.md). 1 RAMB36 in 512x72
// mode. Single write port driven by the Pi (opcode 0x12); single read port for step-4
// lookup/enforcement. Bit-exact twin: rule_store_model.py.
module rule_store (
    input  wire        clk,
    input  wire [8:0]  w_idx,
    input  wire [71:0] w_rule,
    input  wire        w_en,
    input  wire [8:0]  r_idx,
    output reg  [71:0] r_rule
);
    (* ram_style="block" *) reg [71:0] mem[0:511];
    integer k;
    initial begin
        for (k=0;k<512;k=k+1) mem[k] = 72'd0;
        r_rule = 72'd0;
    end
    always @(posedge clk) begin
        if (w_en) mem[w_idx] <= w_rule;
        r_rule <= mem[r_idx];
    end
endmodule
