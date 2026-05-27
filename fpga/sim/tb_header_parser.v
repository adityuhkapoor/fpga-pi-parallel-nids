`timescale 1ns/1ps
// Drives the parser the coordinated golden vectors (generated from packet_capture.py's
// inet_aton + ">HHBBHI" packing) and checks every extracted field, so the FPGA parser
// and the Pi byte layout are verified to agree. Vectors 5/6 (all-ones / all-zero) are
// bit/byte-boundary stress cases. RFC5737 addresses only.
module tb_header_parser;
    localparam FRAME_BYTES = 20;
    localparam FRAME_BITS  = FRAME_BYTES*8;

    reg clk = 1'b0, rst = 1'b1, frame_valid = 1'b0;
    reg  [FRAME_BITS-1:0] frame = {FRAME_BITS{1'b0}};
    wire [31:0] src_ip, dst_ip;
    wire [15:0] src_port, dst_port, pkt_size;
    wire [7:0]  proto, tcp_flags;
    wire        fields_valid;

    header_parser #(.FRAME_BYTES(FRAME_BYTES)) dut (
        .clk(clk), .rst(rst), .frame(frame), .frame_valid(frame_valid),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size), .fields_valid(fields_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    integer errors = 0;
    integer valid_count = 0;
    always @(posedge clk) if (fields_valid) valid_count = valid_count + 1;

    task feed_and_check(
        input integer            vnum,
        input [FRAME_BITS-1:0]   f,
        input [31:0]             e_src,  e_dst,
        input [15:0]             e_sport, e_dport,
        input [7:0]              e_proto, e_flags,
        input [15:0]             e_size
    );
        begin
            // Stimulus 1 ns after each edge so frame_valid is sampled cleanly for exactly
            // one edge (no delta race / double-latch); matches tb_bloom_filter's pattern.
            @(posedge clk); #1; frame = f; frame_valid = 1'b1;
            @(posedge clk); #1; frame_valid = 1'b0;
            @(posedge clk); #1;
            if (src_ip   !== e_src)   begin $display("FAIL v%0d src_ip %08h != %08h", vnum, src_ip,   e_src);   errors=errors+1; end
            if (dst_ip   !== e_dst)   begin $display("FAIL v%0d dst_ip %08h != %08h", vnum, dst_ip,   e_dst);   errors=errors+1; end
            if (src_port !== e_sport) begin $display("FAIL v%0d sport %04h != %04h",  vnum, src_port, e_sport); errors=errors+1; end
            if (dst_port !== e_dport) begin $display("FAIL v%0d dport %04h != %04h",  vnum, dst_port, e_dport); errors=errors+1; end
            if (proto    !== e_proto) begin $display("FAIL v%0d proto %02h != %02h",  vnum, proto,    e_proto); errors=errors+1; end
            if (tcp_flags!== e_flags) begin $display("FAIL v%0d flags %02h != %02h",  vnum, tcp_flags,e_flags); errors=errors+1; end
            if (pkt_size !== e_size)  begin $display("FAIL v%0d size %04h != %04h",   vnum, pkt_size, e_size);  errors=errors+1; end
        end
    endtask

    initial begin
        #20 rst = 1'b0;
        @(posedge clk);

        //            #  20-byte frame (MSB-first)                          src_ip      dst_ip      sport  dport  proto  flags  size
        feed_and_check(1, 160'hc0000201c6336401d43101bb0602003c00000000, 32'hC0000201,32'hC6336401,16'hD431,16'h01BB,8'h06,8'h02,16'h003C);
        feed_and_check(2, 160'hc000020acb00710504d200500618020000000000, 32'hC000020A,32'hCB007105,16'h04D2,16'h0050,8'h06,8'h18,16'h0200);
        feed_and_check(3, 160'hc0000232c63364359c4000351100004700000000, 32'hC0000232,32'hC6336435,16'h9C40,16'h0035,8'h11,8'h00,16'h0047);
        feed_and_check(4, 160'hc0000201c6336401000000000100006200000000, 32'hC0000201,32'hC6336401,16'h0000,16'h0000,8'h01,8'h00,16'h0062);
        feed_and_check(5, 160'hffffffffffffffffffffffffffffffff00000000, 32'hFFFFFFFF,32'hFFFFFFFF,16'hFFFF,16'hFFFF,8'hFF,8'hFF,16'hFFFF);
        feed_and_check(6, 160'h0000000000000000000000000000000000000000, 32'h00000000,32'h00000000,16'h0000,16'h0000,8'h00,8'h00,16'h0000);

        if (valid_count !== 6) begin $display("FAIL: fields_valid pulsed %0d times, expected 6", valid_count); errors=errors+1; end
        if (errors == 0) $display("PASS: header_parser matches all 6 golden vectors");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
