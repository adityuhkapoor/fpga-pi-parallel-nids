`timescale 1ns/1ps
// v2 step 4: on every classify frame, hash src_ip to a rule_store index, read the stored
// rule, output match iff (stored.src_ip == src_ip) AND (stored.epoch == current_rule_epoch).
// 2-phase FSM: phase 0 latches src_ip + epoch (rs_r_idx is combinational, rule_store loads
// rs_r_rule at end of this cycle); phase 1 reads rs_r_rule and emits the match decision.
// Bit-exact twin: rule_lookup_model.py.
module rule_lookup (
    input  wire        clk, rst,
    input  wire [31:0] src_ip,
    input  wire        in_valid,
    input  wire [7:0]  current_rule_epoch,
    // rule_store r-port (combinational idx out, registered rule in)
    output wire [8:0]  rs_r_idx,
    input  wire [71:0] rs_r_rule,
    output reg         match, out_valid,
    output reg  [7:0]  action,
    output reg  [3:0]  severity
);
    localparam [31:0] A1 = 32'h9E3779B1;

    function [8:0] f_idx(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A1; f_idx = p[31:23]; end
    endfunction

    assign rs_r_idx = f_idx(src_ip);

    reg        phase;
    reg [31:0] src_ip_lat;
    reg [7:0]  epoch_lat;

    initial begin match=0; out_valid=0; action=0; severity=0; phase=0; end

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            phase <= 1'b0; match <= 1'b0; action <= 8'd0; severity <= 4'd0;
        end else case (phase)
            1'b0: if (in_valid) begin
                      src_ip_lat <= src_ip;
                      epoch_lat  <= current_rule_epoch;
                      phase      <= 1'b1;
                  end
            1'b1: begin
                      // rs_r_rule layout (72b, MSB-first per PROTOCOL.md):
                      //   [71:40] src_ip(32) | [39:32] action(8) | [31:24] severity_byte (low 4 used)
                      //   | [23:16] epoch(8) | [15:0] reserved(16)
                      if (rs_r_rule[71:40] == src_ip_lat && rs_r_rule[23:16] == epoch_lat) begin
                          match    <= 1'b1;
                          action   <= rs_r_rule[39:32];
                          severity <= rs_r_rule[27:24];   // low 4 bits of severity byte
                      end else begin
                          match    <= 1'b0;
                          action   <= 8'd0;
                          severity <= 4'd0;
                      end
                      out_valid <= 1'b1;
                      phase     <= 1'b0;
                  end
        endcase
    end
endmodule
