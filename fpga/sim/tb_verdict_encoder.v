`timescale 1ns/1ps
// Tier-1 format conformance: drives the 8 VERDICT_VECTORS.md field sets into
// verdict_encoder and checks it emits each exact 20-byte frame. Vectors cover the seq
// boundaries (255, wrap-to-0) and the post-reset all-zero "no verdict" frame.
module tb_verdict_encoder;
    localparam FRAME_BYTES = 20;
    localparam FRAME_BITS  = FRAME_BYTES*8;

    reg clk = 1'b0, rst = 1'b1, classify_valid = 1'b0;
    reg [2:0] hit_mask = 3'd0;
    reg [1:0] severity = 2'd0;
    reg       escalate = 1'b0;
    reg [7:0] seq = 8'd0;
    wire [FRAME_BITS-1:0] verdict_frame;
    wire                  verdict_valid;

    verdict_encoder #(.FRAME_BYTES(FRAME_BYTES)) dut (
        .clk(clk), .rst(rst), .classify_valid(classify_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .seq(seq),
        .verdict_frame(verdict_frame), .verdict_valid(verdict_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    integer errors = 0;

    task drive_check(
        input integer            vnum,
        input [2:0]              mask,
        input [1:0]              sev,
        input                    esc,
        input [7:0]              sq,
        input [FRAME_BITS-1:0]   exp
    );
        begin
            // Stimulus changes 1 ns after each edge so inputs never toggle exactly on a
            // clock edge (avoids the classify_valid/sample delta race).
            @(posedge clk); #1;
            hit_mask = mask; severity = sev; escalate = esc; seq = sq; classify_valid = 1'b1;
            @(posedge clk); #1;       // encoder registered the frame; valid is high this cycle
            if (!verdict_valid)
                begin $display("FAIL v%0d verdict_valid low", vnum); errors=errors+1; end
            if (verdict_frame !== exp)
                begin $display("FAIL v%0d frame %h != %h", vnum, verdict_frame, exp); errors=errors+1; end
            classify_valid = 1'b0;
        end
    endtask

    initial begin
        #20 rst = 1'b0;

        //          #  mask  sev  esc  seq    expected 20-byte frame
        drive_check(1, 3'b000, 2'd0, 1'b0, 8'd1,   160'ha500000001000000000000000000000000000000);
        drive_check(2, 3'b001, 2'd3, 1'b1, 8'd2,   160'ha501030102000000000000000000000000000000);
        drive_check(3, 3'b010, 2'd2, 1'b0, 8'd3,   160'ha502020003000000000000000000000000000000);
        drive_check(4, 3'b100, 2'd1, 1'b0, 8'd4,   160'ha504010004000000000000000000000000000000);
        drive_check(5, 3'b111, 2'd3, 1'b1, 8'd5,   160'ha507030105000000000000000000000000000000);
        drive_check(6, 3'b000, 2'd0, 1'b0, 8'd255, 160'ha5000000ff000000000000000000000000000000);
        drive_check(7, 3'b001, 2'd3, 1'b1, 8'd0,   160'ha501030100000000000000000000000000000000);

        // Vector 8: reset -> all-zero "no verdict" frame, magic != 0xA5.
        @(posedge clk); #1; rst = 1'b1; classify_valid = 1'b0;
        @(posedge clk); #1;
        if (verdict_frame !== {FRAME_BITS{1'b0}})
            begin $display("FAIL v8 reset frame %h != 0", verdict_frame); errors=errors+1; end
        if (verdict_frame[159:152] === 8'hA5)
            begin $display("FAIL v8 reset magic is 0xA5"); errors=errors+1; end

        if (errors == 0) $display("PASS: verdict_encoder matches all 8 format vectors");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
