`timescale 1ns/1ps
// flow_table unit test (mirrors flow_table_model.py):
//  - rate flood + window-reset + vertical scan (same v1.1 invariants scan_rate held);
//  - DIRECTED collision-evict test: src_a (0xCB007105) and src_b (0x0A000CF5) share bucket
//    0xEEC but differ in fp -- step 3 must EVICT src_a's state when src_b arrives, so the
//    second visit by src_a sees a fresh cell (no v1.1-style silent OR merge).
module tb_flow_table;
    reg clk = 1'b0, rst = 1'b1, in_valid = 1'b0;
    reg [31:0] src_ip = 32'd0, dst_ip = 32'd0;
    reg [15:0] dst_port = 16'd0, pkt_size = 16'd0, frame_count = 16'd0;
    reg [7:0]  proto = 8'd0, tcp_flags = 8'd0;
    wire port_scan_hit, rate_hit, out_valid;
    integer errors = 0, i;

    flow_table dut (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags),
        .pkt_size(pkt_size), .frame_count(frame_count),
        .port_thresh(16'd5), .host_thresh(16'd5), .rate_thresh(16'd8),
        .in_valid(in_valid),
        .port_scan_hit(port_scan_hit), .rate_hit(rate_hit), .out_valid(out_valid)
    );

    always #5 clk = ~clk;

    task feed(input [31:0] s, input [31:0] d, input [15:0] dp,
              input [7:0] pr, input [7:0] fl, input [15:0] sz, input [15:0] fc);
        begin
            @(posedge clk); #1;
            src_ip = s; dst_ip = d; dst_port = dp; proto = pr; tcp_flags = fl;
            pkt_size = sz; frame_count = fc; in_valid = 1'b1;
            @(posedge clk); #1; in_valid = 1'b0;
            @(posedge out_valid); #1;
        end
    endtask

    task scan_port(input [15:0] fc, input [15:0] port, input expect_hit);
        begin
            feed(32'hCB007106, 32'hC0000201, port, 8'd6, 8'h02, 16'd60, fc);
            if (port_scan_hit !== expect_hit) begin
                $display("FAIL: scan frame %0d port %0d hit=%b exp %b",
                         fc, port, port_scan_hit, expect_hit); errors = errors + 1;
            end
        end
    endtask

    initial begin
        #20 rst = 1'b0;
        @(posedge clk);

        // --- rate flood (same shape as tb_scan_rate) ---
        for (i = 0; i < 8; i = i + 1) begin
            feed(32'hC0000220, 32'hC0000221, 16'd9999, 8'd17, 8'h00, 16'd60, i[15:0]);
            if (i < 7 && rate_hit !== 1'b0)
                begin $display("FAIL: rate fired early at pkt %0d", i); errors=errors+1; end
            if (i == 7 && rate_hit !== 1'b1)
                begin $display("FAIL: rate did not fire on the 8th pkt"); errors=errors+1; end
        end

        // --- window reset ---
        feed(32'hC0000220, 32'hC0000221, 16'd9999, 8'd17, 8'h00, 16'd60, 16'd16);
        if (rate_hit !== 1'b0)
            begin $display("FAIL: rate did not reset across window boundary"); errors=errors+1; end

        // --- vertical scan (fires on the 5th distinct-bit port) ---
        scan_port(16'd0, 16'd1,  1'b0);
        scan_port(16'd1, 16'd3,  1'b0);
        scan_port(16'd2, 16'd7,  1'b0);
        scan_port(16'd3, 16'd13, 1'b0);
        scan_port(16'd4, 16'd21, 1'b1);

        // --- collision-evict test (step 3's differentiator) ---
        // src_a sends 4 SYNs to distinct-bit ports -> dport_fp popcount = 4 (no trip yet)
        feed(32'hCB007105, 32'hC0000020, 16'd1,  8'd6, 8'h02, 16'd60, 16'd0);
        feed(32'hCB007105, 32'hC0000020, 16'd3,  8'd6, 8'h02, 16'd60, 16'd1);
        feed(32'hCB007105, 32'hC0000020, 16'd7,  8'd6, 8'h02, 16'd60, 16'd2);
        feed(32'hCB007105, 32'hC0000020, 16'd13, 8'd6, 8'h02, 16'd60, 16'd3);
        if (port_scan_hit !== 1'b0)
            begin $display("FAIL: pre-eviction src_a should NOT trip yet"); errors=errors+1; end
        // src_b (0x0A000CF5) -- collides with src_a in bucket (0xEEC) -- evicts the cell
        feed(32'h0A000CF5, 32'hC0000020, 16'd21, 8'd6, 8'h02, 16'd60, 16'd4);
        // src_a returns: state was evicted, so popcount = 1 (only this packet's port_bit), no trip
        feed(32'hCB007105, 32'hC0000020, 16'd42, 8'd6, 8'h02, 16'd60, 16'd5);
        if (port_scan_hit !== 1'b0) begin
            $display("FAIL: src_a after eviction must NOT trip port_scan (v1.1 silent-merge bug)");
            errors=errors+1;
        end

        if (errors == 0)
            $display("PASS: tb_flow_table (rate/scan/window-reset + collision-evict)");
        else
            $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
