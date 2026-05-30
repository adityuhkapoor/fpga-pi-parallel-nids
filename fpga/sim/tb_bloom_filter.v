`timescale 1ns/1ps
// Bloom unit test: (1) the locked C2 set baked into bloom_init.mem still hits per the v1
// rules; (2) port B can write+read back a known word; (3) zeroing the BRAM via port B kills
// the hit (proves port-B writes affect port-A queries).
module tb_bloom_filter;
    localparam [31:0] C2_A = 32'hC6336401;
    localparam [31:0] C2_B = 32'hCB007105;
    localparam [31:0] C2_C = 32'hC0000263;
    localparam [31:0] CLN  = 32'hC0000201;
    localparam [31:0] CLN2 = 32'h0A000001;

    reg         clk = 1'b0, rst = 1'b1, in_valid = 1'b0;
    reg [31:0]  src_ip = 32'd0, dst_ip = 32'd0;
    wire        bloom_hit, out_valid;
    // step-2 port B
    reg  [11:0] w_addr = 12'd0, r_addr = 12'd0;
    reg  [15:0] w_data = 16'd0;
    reg         w_en = 1'b0, r_en = 1'b0;
    wire [15:0] r_data;

    bloom_filter dut (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip), .in_valid(in_valid),
        .bloom_hit(bloom_hit), .out_valid(out_valid),
        .w_addr(w_addr), .w_data(w_data), .w_en(w_en),
        .r_addr(r_addr), .r_en(r_en), .r_data(r_data)
    );

    always #5 clk = ~clk;
    integer errors = 0, k;

    task query_check(input integer qnum, input [31:0] s, input [31:0] d, input e_hit);
        begin
            @(posedge clk); #1; src_ip = s; dst_ip = d; in_valid = 1'b1;
            @(posedge clk); #1; in_valid = 1'b0;
            @(posedge out_valid); #1;
            if (bloom_hit !== e_hit)
                begin $display("FAIL q%0d src=%08h dst=%08h hit=%b exp %b",
                               qnum, s, d, bloom_hit, e_hit); errors=errors+1; end
        end
    endtask

    initial begin
        #20 rst = 1'b0;
        @(posedge clk);

        // -- existing C2-set hit/miss checks (validates the 6-phase serial read path) --
        query_check(1, C2_A, CLN, 1'b1);
        query_check(2, C2_B, CLN, 1'b1);
        query_check(3, C2_C, CLN, 1'b1);
        query_check(4, CLN, C2_A, 1'b1);
        query_check(5, CLN, C2_B, 1'b1);
        query_check(6, CLN, C2_C, 1'b1);
        query_check(7, CLN, CLN2, 1'b0);

        // -- port-B write+readback round-trip on a known word --
        @(posedge clk); #1;
        w_addr = 12'h100; w_data = 16'hBEEF; w_en = 1'b1;
        @(posedge clk); #1; w_en = 1'b0;
        r_addr = 12'h100; r_en = 1'b1;
        @(posedge clk); #1; r_en = 1'b0;
        @(posedge clk); #1;                       // r_data registered, settle
        if (r_data !== 16'hBEEF) begin $display("FAIL port-B readback %04h != BEEF", r_data); errors=errors+1; end

        // -- wipe entire BRAM via port B, re-query: C2_A must now MISS --
        for (k = 0; k < 4096; k = k + 1) begin
            w_addr = k[11:0]; w_data = 16'd0; w_en = 1'b1;
            @(posedge clk); #1;
        end
        w_en = 1'b0;
        query_check(8, C2_A, CLN, 1'b0);          // bloom wiped -> miss

        if (errors == 0) $display("PASS: bloom_filter v2 - C2 hits + port-B write/read + wipe-then-miss");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
