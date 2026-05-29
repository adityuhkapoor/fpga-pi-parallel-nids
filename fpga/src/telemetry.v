`timescale 1ns/1ps
// Telemetry wrapper: cms + hll, a WINDOW_CYCLES tumbling-window timer (win_tick), a per-window
// snapshot latched at the boundary, and a top-1 heavy-hitter tracker (src with the largest CMS
// estimate this window). force_tick lets a testbench trigger a boundary deterministically; on
// silicon the timer drives it. Bit-exact twin: telemetry_model.py.
module telemetry #(parameter WINDOW_CYCLES = 100000000) (
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire        upd_valid,            // a packet to count
    input  wire        force_tick,           // tb-only deterministic window boundary
    input  wire [31:0] q_ip,
    input  wire        q_valid,              // CMS point-query passthrough
    output wire [13:0] q_count,
    output wire        q_done,
    output wire [47:0] live_harmonic_sum,    // current window (opcode 0x03)
    output wire [11:0] live_zeros,
    output reg  [15:0] snap_window,          // last completed window (opcode 0x02)
    output reg  [31:0] snap_total,
    output reg  [47:0] snap_harmonic_sum,
    output reg  [11:0] snap_zeros,
    output reg  [13:0] snap_top1_count,
    output reg  [31:0] snap_top1_key
);
    reg [31:0] wcnt;
    reg        timer_tick;
    always @(posedge clk) begin
        timer_tick <= 1'b0;
        if (rst) wcnt <= WINDOW_CYCLES - 1;
        else if (wcnt == 0) begin timer_tick <= 1'b1; wcnt <= WINDOW_CYCLES - 1; end
        else wcnt <= wcnt - 32'd1;
    end
    wire win_tick = timer_tick | force_tick;

    wire [13:0] c_upd_count;
    wire        c_upd_done;
    cms u_cms (.clk(clk), .rst(rst), .src_ip(src_ip), .upd_valid(upd_valid), .win_tick(win_tick),
               .q_ip(q_ip), .q_valid(q_valid), .q_count(q_count), .q_done(q_done),
               .upd_count(c_upd_count), .upd_done(c_upd_done));
    hll u_hll (.clk(clk), .rst(rst), .src_ip(src_ip), .upd_valid(upd_valid), .win_tick(win_tick),
               .q_valid(1'b0), .harmonic_sum(live_harmonic_sum), .zeros(live_zeros), .q_done());

    reg [31:0] upd_key;                       // src held across the cms pipeline for top-1 attribution
    always @(posedge clk) if (upd_valid) upd_key <= src_ip;

    reg [15:0] window_index;
    reg [31:0] total_packets;
    reg [13:0] top1_count;
    reg [31:0] top1_key;

    always @(posedge clk) begin
        if (rst) begin
            window_index <= 16'd0; total_packets <= 32'd0; top1_count <= 14'd0; top1_key <= 32'd0;
            snap_window <= 16'd0; snap_total <= 32'd0; snap_harmonic_sum <= 48'h080000000000;
            snap_zeros <= 12'd2048; snap_top1_count <= 14'd0; snap_top1_key <= 32'd0;
        end else if (win_tick) begin          // latch completed window (pre-reset values), then clear
            snap_window <= window_index; snap_total <= total_packets;
            snap_harmonic_sum <= live_harmonic_sum; snap_zeros <= live_zeros;
            snap_top1_count <= top1_count; snap_top1_key <= top1_key;
            window_index <= window_index + 16'd1; total_packets <= 32'd0;
            top1_count <= 14'd0; top1_key <= 32'd0;
        end else begin
            if (upd_valid) total_packets <= total_packets + 32'd1;
            if (c_upd_done && c_upd_count > top1_count) begin
                top1_count <= c_upd_count; top1_key <= upd_key;
            end
        end
    end
endmodule
