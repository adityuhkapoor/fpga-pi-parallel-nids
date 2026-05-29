`timescale 1ns/1ps
// Replays the gen_telemetry_golden STREAM into cms.v, point-queries the 5 golden keys, and
// checks q_count == {9,3,5,1,0}; then win_tick and re-queries the heavy hitter -> 0 (lazy reset).
// Keep the expected values in sync with `python3 gen_telemetry_golden.py`.
module tb_cms;
    reg clk = 1'b0, rst = 1'b1;
    reg [31:0] src_ip = 0, q_ip = 0;
    reg upd_valid = 0, win_tick = 0, q_valid = 0;
    wire [13:0] q_count;
    wire q_done;

    cms dut (.clk(clk), .rst(rst), .src_ip(src_ip), .upd_valid(upd_valid),
             .win_tick(win_tick), .q_ip(q_ip), .q_valid(q_valid),
             .q_count(q_count), .q_done(q_done));

    always #5 clk = ~clk;   // 100 MHz

    integer errors = 0;

    task do_update(input [31:0] ip);
        begin
            src_ip = ip; upd_valid = 1'b1;
            @(posedge clk); #1; upd_valid = 1'b0;
            repeat (4) @(posedge clk); #1;       // FSM: phase1 -> phase2 -> phase3 (min) -> back to 0
        end
    endtask

    task do_tick;
        begin win_tick = 1'b1; @(posedge clk); #1; win_tick = 1'b0; @(posedge clk); #1; end
    endtask

    task check_query(input [31:0] ip, input [13:0] exp, input [127:0] tag);
        begin
            q_ip = ip; q_valid = 1'b1;
            @(posedge clk); #1; q_valid = 1'b0;
            while (!q_done) begin @(posedge clk); #1; end
            if (q_count !== exp) begin
                $display("FAIL [%0s]: q_count %0d != %0d (ip %08h)", tag, q_count, exp, ip);
                errors = errors + 1;
            end
            @(posedge clk); #1;
        end
    endtask

    // STREAM: CB007105 x9, C0000201 x3, 0A000001/2/3, C0000263 x5
    integer i;
    initial begin
        #20 rst = 1'b0; @(posedge clk); #1;
        for (i=0;i<9;i=i+1) do_update(32'hCB007105);
        for (i=0;i<3;i=i+1) do_update(32'hC0000201);
        do_update(32'h0A000001); do_update(32'h0A000002); do_update(32'h0A000003);
        for (i=0;i<5;i=i+1) do_update(32'hC0000263);

        check_query(32'hCB007105, 14'd9, "hh");
        check_query(32'hC0000201, 14'd3, "rup");
        check_query(32'hC0000263, 14'd5, "udp");
        check_query(32'h0A000001, 14'd1, "one");
        check_query(32'h08080808, 14'd0, "miss");

        do_tick;                                  // window boundary -> lazy reset
        check_query(32'hCB007105, 14'd0, "reset");

        if (errors == 0) $display("PASS: tb_cms heavy-hitter counts + lazy reset");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
