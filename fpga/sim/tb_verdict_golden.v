`timescale 1ns/1ps
// Tier-2 cross-check: drives the 6 VERDICT_GOLDEN.md headers through the full pipeline
// (spi_slave_rx -> header_parser -> bloom -> verdict_encoder) over a mode-0 SPI master
// and asserts each returned 20-byte verdict matches the Pi CPU reference. The verdict for
// frame K ships during transfer K+1 (one-frame lag), so transfer 1 returns "no verdict"
// and a 7th flush transfer collects frame 6's verdict.
module tb_verdict_golden;
    localparam FRAME_BYTES = 32;
    localparam FRAME_BITS  = FRAME_BYTES*8;
    localparam HALF        = 250;   // 2 MHz SCLK

    reg clk = 1'b0, btnC = 1'b1;
    reg sclk = 1'b0, cs_n = 1'b1, mosi = 1'b0;
    wire miso;
    wire [15:0] led;

    nids_top dut (
        .clk(clk), .btnC(btnC), .sclk(sclk), .cs_n(cs_n), .mosi(mosi), .miso(miso), .led(led)
    );

    always #5 clk = ~clk;   // 100 MHz

    integer errors = 0;

    task send_byte(input [7:0] tx, output [7:0] rx);
        integer i;
        begin
            for (i = 7; i >= 0; i = i - 1) begin
                mosi = tx[i];
                #HALF sclk = 1'b1;
                #(HALF/2) rx[i] = miso;
                #(HALF/2) sclk = 1'b0;
            end
        end
    endtask

    task send_frame(input [FRAME_BITS-1:0] txf, output [FRAME_BITS-1:0] rxf);
        integer j;
        reg [7:0] rb;
        begin
            cs_n = 1'b0;
            #(HALF*2);
            for (j = 0; j < FRAME_BYTES; j = j + 1) begin
                send_byte(txf[(FRAME_BITS-1-8*j) -:8], rb);
                rxf[(FRAME_BITS-1-8*j) -:8] = rb;
            end
            #HALF cs_n = 1'b1;
            #(HALF*8);   // let the pipeline land the verdict before the next transfer
        end
    endtask

    reg [FRAME_BITS-1:0] hdr  [1:6];
    reg [FRAME_BITS-1:0] gold [1:6];
    reg [FRAME_BITS-1:0] rx   [1:7];
    integer k;

    initial begin
        hdr[1]  = 256'hc0000201c0000202303900500602003c00000000000000000000000000000000;  // clean TCP
        gold[1] = 256'ha500000001000000000000000000000000000000000000000000000000000000;
        hdr[2]  = 256'hc0000201c6336401303901bb0602003c00000000000000000000000000000000;  // dst C2
        gold[2] = 256'ha501030102000000000000000000000000000000000000000000000000000000;
        hdr[3]  = 256'hcb007105c0000201303900500602003c00000000000000000000000000000000;  // src C2
        gold[3] = 256'ha501030103000000000000000000000000000000000000000000000000000000;
        hdr[4]  = 256'hc0000232c0000263303900351100003c00000000000000000000000000000000;  // dst C2, UDP
        gold[4] = 256'ha501030104000000000000000000000000000000000000000000000000000000;
        hdr[5]  = 256'h0a0000010a000002303900351100003c00000000000000000000000000000000;  // clean UDP
        gold[5] = 256'ha500000005000000000000000000000000000000000000000000000000000000;
        hdr[6]  = 256'hc6336401cb007105303900500602003c00000000000000000000000000000000;  // both C2
        gold[6] = 256'ha501030106000000000000000000000000000000000000000000000000000000;

        #40 btnC = 1'b0;          // release reset
        @(posedge clk);

        for (k = 1; k <= 6; k = k + 1) send_frame(hdr[k], rx[k]);
        send_frame({FRAME_BITS{1'b0}}, rx[7]);   // flush frame 6's verdict

        // transfer 1: no prior frame -> all-zero no-verdict
        if (rx[1] !== {FRAME_BITS{1'b0}})
            begin $display("FAIL t1 expected no-verdict, got %h", rx[1]); errors=errors+1; end

        // transfer K+1 returns frame K's verdict
        for (k = 1; k <= 6; k = k + 1)
            if (rx[k+1] !== gold[k])
                begin $display("FAIL golden %0d: %h != %h", k, rx[k+1], gold[k]); errors=errors+1; end

        if (errors == 0) $display("PASS: full pipeline matches all 6 verdict golden vectors");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
