`timescale 1ns/1ps
// Defaults restore on reset (5, 5, 8); writes via id 0x00/0x01/0x02 land in the right
// register; direct taps update; unknown ids are ignored. Keep in sync with thresholds_model.py.
module tb_thresholds;
    reg         clk = 1'b0, rst = 1'b1, w_en = 1'b0;
    reg  [7:0]  w_id = 8'd0, r_id = 8'd0;
    reg  [15:0] w_val = 16'd0;
    wire [15:0] r_val, port_thresh, host_thresh, rate_thresh;

    thresholds dut (.clk(clk), .rst(rst), .w_id(w_id), .w_val(w_val), .w_en(w_en),
                    .r_id(r_id), .r_val(r_val),
                    .port_thresh(port_thresh), .host_thresh(host_thresh), .rate_thresh(rate_thresh));
    always #5 clk = ~clk;
    integer errors = 0;

    task do_write(input [7:0] id, input [15:0] val);
        begin w_id = id; w_val = val; w_en = 1'b1; @(posedge clk); #1; w_en = 1'b0; end
    endtask
    task do_read(input [7:0] id);
        begin r_id = id; @(posedge clk); #1; @(posedge clk); #1; end
    endtask
    task expect_val(input [15:0] exp, input [127:0] tag);
        begin if (r_val !== exp) begin
            $display("FAIL [%0s]: r_val %0d != %0d", tag, r_val, exp);
            errors = errors + 1; end
        end
    endtask
    task expect_tap(input [15:0] got, input [15:0] exp, input [127:0] tag);
        begin if (got !== exp) begin
            $display("FAIL [%0s]: tap %0d != %0d", tag, got, exp);
            errors = errors + 1; end
        end
    endtask

    initial begin
        #20 rst = 1'b0; @(posedge clk); #1;
        expect_tap(port_thresh, 16'd5, "port_def");
        expect_tap(host_thresh, 16'd5, "host_def");
        expect_tap(rate_thresh, 16'd8, "rate_def");
        do_read(8'h00); expect_val(16'd5, "rd_port_def");
        do_read(8'h02); expect_val(16'd8, "rd_rate_def");

        do_write(8'h00, 16'd12); do_read(8'h00); expect_val(16'd12, "port_12");
        expect_tap(port_thresh, 16'd12, "port_tap_12");
        do_write(8'h02, 16'd99); do_read(8'h02); expect_val(16'd99, "rate_99");

        // unknown id ignored
        do_write(8'hEE, 16'hAAAA);
        do_read(8'h00); expect_val(16'd12, "port_unchanged");
        do_read(8'hEE); expect_val(16'd0, "unknown_zero");

        if (errors == 0) $display("PASS: tb_thresholds defaults + write/read + ignore unknown");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
