`timescale 1ns/1ps
// Write 3 distinct rules at known indices, read them back, assert each read returns what
// was written. 72-bit rule layout per PROTOCOL.md: {src_ip:32, action:8, sev:8, epoch:8, rsv:16}.
module tb_rule_store;
    reg         clk = 1'b0;
    reg [8:0]   w_idx = 9'd0, r_idx = 9'd0;
    reg [71:0]  w_rule = 72'd0;
    reg         w_en = 1'b0;
    wire [71:0] r_rule;

    rule_store dut (.clk(clk), .w_idx(w_idx), .w_rule(w_rule), .w_en(w_en),
                    .r_idx(r_idx), .r_rule(r_rule));
    always #5 clk = ~clk;
    integer errors = 0;

    task do_write(input [8:0] idx, input [71:0] rule);
        begin w_idx = idx; w_rule = rule; w_en = 1'b1;
              @(posedge clk); #1; w_en = 1'b0; end
    endtask
    task do_read(input [8:0] idx);
        begin r_idx = idx; @(posedge clk); #1; @(posedge clk); #1; end   // 1-cyc read latency + settle
    endtask
    task expect_rule(input [71:0] exp, input [127:0] tag);
        begin if (r_rule !== exp) begin
            $display("FAIL [%0s]: r_rule %018h != %018h", tag, r_rule, exp);
            errors = errors + 1; end
        end
    endtask

    localparam [71:0] R0 = 72'hCB007105_05_03_07_0000;
    localparam [71:0] R1 = 72'hC0000201_02_02_64_0000;
    localparam [71:0] R2 = 72'h0A000005_07_01_FF_0000;

    initial begin
        #20;
        do_write(9'd42,  R0);
        do_write(9'd100, R1);
        do_write(9'd511, R2);

        do_read(9'd42);  expect_rule(R0, "r42");
        do_read(9'd100); expect_rule(R1, "r100");
        do_read(9'd511); expect_rule(R2, "r511");

        if (errors == 0) $display("PASS: tb_rule_store write/read roundtrip");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
