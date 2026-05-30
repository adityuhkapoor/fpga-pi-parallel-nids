`timescale 1ns/1ps
// Runtime thresholds: PORT/HOST/RATE for scan_rate, writable via opcode 0x11. Power-on
// reset restores the v1.1 defaults (5, 5, 8). Direct port_/host_/rate_thresh taps feed
// scan_rate combinationally; r_val is registered for the opcode 0x14 read response.
// Bit-exact twin: thresholds_model.py.
module thresholds (
    input  wire        clk, rst,
    input  wire [7:0]  w_id,
    input  wire [15:0] w_val,
    input  wire        w_en,
    input  wire [7:0]  r_id,
    output reg  [15:0] r_val,
    output wire [15:0] port_thresh, host_thresh, rate_thresh
);
    reg [15:0] port_r, host_r, rate_r;
    assign port_thresh = port_r;
    assign host_thresh = host_r;
    assign rate_thresh = rate_r;

    initial begin port_r = 16'd5; host_r = 16'd5; rate_r = 16'd8; r_val = 16'd0; end

    always @(posedge clk) begin
        if (rst) begin port_r <= 16'd5; host_r <= 16'd5; rate_r <= 16'd8; end
        else if (w_en) case (w_id)
            8'h00: port_r <= w_val;
            8'h01: host_r <= w_val;
            8'h02: rate_r <= w_val;
            default: ;
        endcase
        case (r_id)
            8'h00:   r_val <= port_r;
            8'h01:   r_val <= host_r;
            8'h02:   r_val <= rate_r;
            default: r_val <= 16'd0;
        endcase
    end
endmodule
