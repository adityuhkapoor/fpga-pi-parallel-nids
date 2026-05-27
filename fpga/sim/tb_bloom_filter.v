`timescale 1ns/1ps
// Bloom unit test against bloom_init.mem (the locked test C2 set, CLASSIFIER.md):
// each of the 3 C2 IPs must hit on the src side and on the dst side; a non-C2 IP with
// a non-C2 partner must miss. Confirms the hashing + dual-port lookup agree with the
// Pi-generated bit-array.
module tb_bloom_filter;
    localparam [31:0] C2_A = 32'hC6336401;   // 198.51.100.1
    localparam [31:0] C2_B = 32'hCB007105;   // 203.0.113.5
    localparam [31:0] C2_C = 32'hC0000263;   // 192.0.2.99
    localparam [31:0] CLN  = 32'hC0000201;   // 192.0.2.1 (not on the list)
    localparam [31:0] CLN2 = 32'h0A000001;   // 10.0.0.1  (not on the list)

    reg clk = 1'b0, rst = 1'b1, in_valid = 1'b0;
    reg [31:0] src_ip = 32'd0, dst_ip = 32'd0;
    wire bloom_hit, out_valid;

    bloom_filter dut (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .in_valid(in_valid), .bloom_hit(bloom_hit), .out_valid(out_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    integer errors = 0;

    task query_check(
        input integer    qnum,
        input [31:0]      s,
        input [31:0]      d,
        input             e_hit
    );
        begin
            // Stimulus 1 ns after each edge so in_valid is sampled cleanly (no delta race).
            @(posedge clk); #1; src_ip = s; dst_ip = d; in_valid = 1'b1;
            @(posedge clk); #1; in_valid = 1'b0;
            @(posedge out_valid); #1;     // wait for the multi-cycle lookup to finish
            if (bloom_hit !== e_hit)
                begin $display("FAIL q%0d src=%08h dst=%08h hit=%b exp %b",
                               qnum, s, d, bloom_hit, e_hit); errors=errors+1; end
        end
    endtask

    initial begin
        #20 rst = 1'b0;
        @(posedge clk);

        // each C2 IP hits on the src side (clean partner) ...
        query_check(1, C2_A, CLN, 1'b1);
        query_check(2, C2_B, CLN, 1'b1);
        query_check(3, C2_C, CLN, 1'b1);
        // ... and on the dst side
        query_check(4, CLN, C2_A, 1'b1);
        query_check(5, CLN, C2_B, 1'b1);
        query_check(6, CLN, C2_C, 1'b1);
        // both clean -> miss
        query_check(7, CLN, CLN2, 1'b0);

        if (errors == 0) $display("PASS: bloom_filter hits all 3 C2 IPs, misses clean");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
