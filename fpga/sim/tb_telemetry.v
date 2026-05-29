`timescale 1ns/1ps
// Two checks: (1) dut with a large window + force_tick replays the golden STREAM, then a
// boundary, and the snapshot must match the twin (window 0, total 20, sum 0x07FB92000000,
// zeros 2042, top1 CB007105=9); (2) dut_timer with WINDOW_CYCLES=20 must auto-fire win_tick
// (snap_window advances with no force). Keep in sync with `python3 gen_telemetry_golden.py`.
module tb_telemetry;
    reg clk = 1'b0, rst = 1'b1;
    reg [31:0] src_ip = 0;
    reg upd_valid = 0, force_tick = 0;
    wire [15:0] snap_window;  wire [31:0] snap_total;  wire [47:0] snap_harmonic_sum;
    wire [11:0] snap_zeros;   wire [13:0] snap_top1_count;  wire [31:0] snap_top1_key;

    telemetry #(.WINDOW_CYCLES(100000)) dut (
        .clk(clk), .rst(rst), .src_ip(src_ip), .upd_valid(upd_valid), .force_tick(force_tick),
        .q_ip(32'd0), .q_valid(1'b0), .q_count(), .q_done(),
        .live_harmonic_sum(), .live_zeros(),
        .snap_window(snap_window), .snap_total(snap_total), .snap_harmonic_sum(snap_harmonic_sum),
        .snap_zeros(snap_zeros), .snap_top1_count(snap_top1_count), .snap_top1_key(snap_top1_key));

    // free-running timer dut: small window, no stimulus -> must auto-tick
    wire [15:0] t_window;
    telemetry #(.WINDOW_CYCLES(20)) dut_timer (
        .clk(clk), .rst(rst), .src_ip(32'd0), .upd_valid(1'b0), .force_tick(1'b0),
        .q_ip(32'd0), .q_valid(1'b0), .q_count(), .q_done(),
        .live_harmonic_sum(), .live_zeros(),
        .snap_window(t_window), .snap_total(), .snap_harmonic_sum(),
        .snap_zeros(), .snap_top1_count(), .snap_top1_key());

    always #5 clk = ~clk;
    integer errors = 0, i;

    task do_update(input [31:0] ip);
        begin
            src_ip = ip; upd_valid = 1'b1;
            @(posedge clk); #1; upd_valid = 1'b0;
            repeat (7) @(posedge clk); #1;     // both cms (4) and hll (5) finish; +margin
        end
    endtask

    initial begin
        #20 rst = 1'b0; @(posedge clk); #1;
        for (i=0;i<9;i=i+1) do_update(32'hCB007105);
        for (i=0;i<3;i=i+1) do_update(32'hC0000201);
        do_update(32'h0A000001); do_update(32'h0A000002); do_update(32'h0A000003);
        for (i=0;i<5;i=i+1) do_update(32'hC0000263);

        force_tick = 1'b1; @(posedge clk); #1; force_tick = 1'b0; @(posedge clk); #1;

        if (snap_window     !== 16'd0)            begin $display("FAIL window %0d",snap_window); errors=errors+1; end
        if (snap_total      !== 32'd20)           begin $display("FAIL total %0d",snap_total); errors=errors+1; end
        if (snap_harmonic_sum !== 48'h07FB92000000) begin $display("FAIL sum %012h",snap_harmonic_sum); errors=errors+1; end
        if (snap_zeros      !== 12'd2042)         begin $display("FAIL zeros %0d",snap_zeros); errors=errors+1; end
        if (snap_top1_count !== 14'd9)            begin $display("FAIL top1_count %0d",snap_top1_count); errors=errors+1; end
        if (snap_top1_key   !== 32'hCB007105)     begin $display("FAIL top1_key %08h",snap_top1_key); errors=errors+1; end

        if (t_window === 16'd0) begin $display("FAIL timer never fired (t_window=0)"); errors=errors+1; end

        if (errors == 0) $display("PASS: tb_telemetry snapshot + top-1 + auto-window-timer");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
