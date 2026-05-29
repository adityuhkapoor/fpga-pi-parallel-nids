`timescale 1ns/1ps
// Replays the gen_telemetry_golden STREAM into hll.v and checks the scaled harmonic sum and
// zero-register count against the twin (6 distinct srcs -> zeros 2042, sum 0x07FB92000000),
// then win_tick -> reset to the empty state (sum 2^43, zeros 2048). Keep in sync with
// `python3 gen_telemetry_golden.py`. The cardinality estimate itself is checked Pi-side.
module tb_hll;
    reg clk = 1'b0, rst = 1'b1;
    reg [31:0] src_ip = 0;
    reg upd_valid = 0, win_tick = 0, q_valid = 0;
    wire [47:0] harmonic_sum;
    wire [11:0] zeros;
    wire q_done;

    hll dut (.clk(clk), .rst(rst), .src_ip(src_ip), .upd_valid(upd_valid),
             .win_tick(win_tick), .q_valid(q_valid),
             .harmonic_sum(harmonic_sum), .zeros(zeros), .q_done(q_done));

    always #5 clk = ~clk;
    integer errors = 0;

    task do_update(input [31:0] ip);
        begin
            src_ip = ip; upd_valid = 1'b1;
            @(posedge clk); #1; upd_valid = 1'b0;
            repeat (6) @(posedge clk); #1;        // 5-phase fmix+RMW, +1 margin
        end
    endtask

    task expect48(input [47:0] got, input [47:0] exp, input [127:0] tag);
        begin if (got !== exp) begin
            $display("FAIL [%0s]: %012h != %012h", tag, got, exp); errors = errors + 1; end
        end
    endtask

    integer i;
    initial begin
        #20 rst = 1'b0; @(posedge clk); #1;
        for (i=0;i<9;i=i+1) do_update(32'hCB007105);
        for (i=0;i<3;i=i+1) do_update(32'hC0000201);
        do_update(32'h0A000001); do_update(32'h0A000002); do_update(32'h0A000003);
        for (i=0;i<5;i=i+1) do_update(32'hC0000263);

        expect48(harmonic_sum, 48'h07FB92000000, "sum");
        if (zeros !== 12'd2042) begin $display("FAIL zeros %0d != 2042", zeros); errors=errors+1; end

        win_tick = 1'b1; @(posedge clk); #1; win_tick = 1'b0; @(posedge clk); #1;
        expect48(harmonic_sum, 48'h080000000000, "reset_sum");
        if (zeros !== 12'd2048) begin $display("FAIL reset zeros %0d != 2048", zeros); errors=errors+1; end

        if (errors == 0) $display("PASS: tb_hll harmonic sum + zeros + reset");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
