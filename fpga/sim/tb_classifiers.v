`timescale 1ns/1ps
// Integration test for the combined classifier block: bloom + scan_rate aligned into one
// verdict. Checks clean, bloom C2 hit (mask bit0, sev3), rate flood (mask bit2, sev2 on the
// 8th), and a combined C2+flood source (bits 0 and 2, sev3). bloom_init.mem = locked C2 set
// (198.51.100.1 / 203.0.113.5 / 192.0.2.99). frame_count drives the 16-frame window epoch.
module tb_classifiers;
    reg clk = 1'b0, rst = 1'b1, fields_valid = 1'b0;
    reg [31:0] src_ip = 32'd0, dst_ip = 32'd0;
    reg [15:0] src_port = 16'd0, dst_port = 16'd0, pkt_size = 16'd0, frame_count = 16'd0;
    reg [7:0]  proto = 8'd0, tcp_flags = 8'd0;
    wire [2:0] hit_mask;
    wire [1:0] severity;
    wire       escalate, classify_valid;
    integer errors = 0, i;

    classifiers dut (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .src_port(src_port), .dst_port(dst_port), .proto(proto), .tcp_flags(tcp_flags),
        .pkt_size(pkt_size), .frame_count(frame_count), .fields_valid(fields_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate),
        .classify_valid(classify_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    task feed(input [31:0] s, input [31:0] d, input [15:0] dp,
              input [7:0] pr, input [7:0] fl, input [15:0] fc);
        begin
            @(posedge clk); #1;
            src_ip = s; dst_ip = d; dst_port = dp; proto = pr; tcp_flags = fl; frame_count = fc;
            fields_valid = 1'b1;
            @(posedge clk); #1; fields_valid = 1'b0;
            @(posedge classify_valid); #1;
        end
    endtask

    task chk(input [2:0] em, input [1:0] es, input [31:0] id);
        begin
            if (hit_mask !== em || severity !== es) begin
                $display("FAIL: check %0d mask=%b(exp %b) sev=%0d(exp %0d)",
                         id, hit_mask, em, severity, es);
                errors = errors + 1;
            end
        end
    endtask

    initial begin
        #20 rst = 1'b0; @(posedge clk);

        // clean: no C2, one-off UDP -> no hits
        feed(32'hC0000201, 32'hC0000202, 16'd53, 8'd17, 8'h00, 16'd0);
        chk(3'b000, 2'd0, 0);

        // bloom C2 hit: dst is a C2 IP -> bit0, sev3 (single SYN won't trip scan)
        feed(32'hC0000201, 32'hC6336401, 16'd443, 8'd6, 8'h02, 16'd1);
        chk(3'b001, 2'd3, 1);

        // rate flood: 8 packets from a fresh source, frames 2..9 (all epoch 0) -> bit2 on 8th
        for (i = 0; i < 8; i = i + 1) begin
            feed(32'hC0000220, 32'hC0000221, 16'd9999, 8'd17, 8'h00, 16'd2 + i[15:0]);
            if (i < 7)  chk(3'b000, 2'd0, 100 + i);
            if (i == 7) chk(3'b100, 2'd2, 107);
        end

        // combined: a C2 source that also floods, frames 16..23 (all epoch 1) -> bits 0+2 on 8th
        for (i = 0; i < 8; i = i + 1) begin
            feed(32'hC6336401, 32'hC0000221, 16'd9999, 8'd17, 8'h00, 16'd16 + i[15:0]);
            if (i < 7)  chk(3'b001, 2'd3, 200 + i);   // bloom only (rate building)
            if (i == 7) chk(3'b101, 2'd3, 207);       // bloom + rate
        end

        if (errors == 0)
            $display("PASS: tb_classifiers (clean, bloom, flood, combined)");
        else
            $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
