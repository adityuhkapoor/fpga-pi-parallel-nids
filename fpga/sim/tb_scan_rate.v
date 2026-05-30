`timescale 1ns/1ps
// scan_rate unit test (mirrors scan_rate.py / test_scan_rate.py vectors):
//  - rate flood: 8 UDP packets from one source in one window -> rate fires on the 8th
//  - window reset: same source at frame 16 (epoch 1) -> counter restarts, no flood
//  - vertical scan: 5 SYNs to distinct-bit ports -> port-scan fires on the 5th
//    ports 1,3,7,13,21 -> port_bit 8,9,10,12,15 (distinct) so popcount reaches 5.
module tb_scan_rate;
    reg clk = 1'b0, rst = 1'b1, in_valid = 1'b0;
    reg [31:0] src_ip = 32'd0, dst_ip = 32'd0;
    reg [15:0] dst_port = 16'd0, frame_count = 16'd0;
    reg [7:0]  proto = 8'd0, tcp_flags = 8'd0;
    wire port_scan_hit, rate_hit, out_valid;
    integer errors = 0;
    integer i;

    scan_rate dut (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .dst_port(dst_port), .proto(proto), .tcp_flags(tcp_flags),
        .frame_count(frame_count), .in_valid(in_valid),
        .port_thresh(16'd5), .host_thresh(16'd5), .rate_thresh(16'd8),   // v1.1 defaults
        .port_scan_hit(port_scan_hit), .rate_hit(rate_hit), .out_valid(out_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    // drive one packet through the RMW and return once the verdict is valid
    task feed(input [31:0] s, input [31:0] d, input [15:0] dp,
              input [7:0] pr, input [7:0] fl, input [15:0] fc);
        begin
            @(posedge clk); #1;
            src_ip = s; dst_ip = d; dst_port = dp; proto = pr; tcp_flags = fl;
            frame_count = fc; in_valid = 1'b1;
            @(posedge clk); #1; in_valid = 1'b0;
            @(posedge out_valid); #1;
        end
    endtask

    // one SYN of a vertical scan; check the running port_scan verdict
    task scan_port(input [15:0] fc, input [15:0] port, input expect_hit);
        begin
            feed(32'hCB007106, 32'hC0000201, port, 8'd6, 8'h02, fc);
            if (port_scan_hit !== expect_hit) begin
                $display("FAIL: scan frame %0d port %0d hit=%b exp %b",
                         fc, port, port_scan_hit, expect_hit);
                errors = errors + 1;
            end
        end
    endtask

    initial begin
        #20 rst = 1'b0;
        @(posedge clk);

        // rate flood: fires on the 8th packet (RATE_THRESH = 8)
        for (i = 0; i < 8; i = i + 1) begin
            feed(32'hC0000220, 32'hC0000221, 16'd9999, 8'd17, 8'h00, i[15:0]);
            if (i < 7 && rate_hit !== 1'b0) begin
                $display("FAIL: rate fired early at pkt %0d", i); errors = errors + 1;
            end
            if (i == 7 && rate_hit !== 1'b1) begin
                $display("FAIL: rate did not fire on the 8th pkt"); errors = errors + 1;
            end
        end

        // window reset: same source, frame 16 (epoch 1) -> not a flood anymore
        feed(32'hC0000220, 32'hC0000221, 16'd9999, 8'd17, 8'h00, 16'd16);
        if (rate_hit !== 1'b0) begin
            $display("FAIL: rate did not reset across window boundary"); errors = errors + 1;
        end

        // vertical scan: trips on the 5th distinct-bit port (frames 0..4, epoch 0)
        scan_port(16'd0, 16'd1,  1'b0);
        scan_port(16'd1, 16'd3,  1'b0);
        scan_port(16'd2, 16'd7,  1'b0);
        scan_port(16'd3, 16'd13, 1'b0);
        scan_port(16'd4, 16'd21, 1'b1);

        if (errors == 0)
            $display("PASS: tb_scan_rate (rate flood, window reset, vertical scan)");
        else
            $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
