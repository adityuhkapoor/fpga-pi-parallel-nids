`timescale 1ns/1ps
// End-to-end round trip: drives a mode-0 SPI master into nids_top and checks the
// verdict frames shifted back on MISO, pipelined one frame late: the transfer of frame K
// returns frame K-1's verdict; the first transfer returns magic=0x00. Frame A is clean
// (neither IP on the C2 list); frame B's src (CB007105) is a C2 IP -> bloom hit. This
// confirms a hit propagates through the full pipeline; tb_verdict_golden covers the rest.
module tb_nids_top;
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

    // Check a returned verdict frame against the locked layout.
    task check_verdict(input integer n, input [FRAME_BITS-1:0] v,
                       input [7:0] e_magic, input [7:0] e_mask, input [7:0] e_sev,
                       input [7:0] e_flags, input [7:0] e_seq);
        begin
            if (v[FRAME_BITS-1  -: 8] !== e_magic) begin $display("FAIL t%0d magic %02h != %02h", n, v[FRAME_BITS-1  -: 8], e_magic); errors=errors+1; end
            if (v[FRAME_BITS-9  -: 8] !== e_mask)  begin $display("FAIL t%0d mask %02h != %02h",  n, v[FRAME_BITS-9  -: 8], e_mask);  errors=errors+1; end
            if (v[FRAME_BITS-17 -: 8] !== e_sev)   begin $display("FAIL t%0d sev %02h != %02h",   n, v[FRAME_BITS-17 -: 8], e_sev);   errors=errors+1; end
            if (v[FRAME_BITS-25 -: 8] !== e_flags) begin $display("FAIL t%0d flags %02h != %02h", n, v[FRAME_BITS-25 -: 8], e_flags); errors=errors+1; end
            if (v[FRAME_BITS-33 -: 8] !== e_seq)   begin $display("FAIL t%0d seq %02h != %02h",   n, v[FRAME_BITS-33 -: 8], e_seq);   errors=errors+1; end
            if (v[FRAME_BITS-41:0]    !== {(FRAME_BITS-40){1'b0}}) begin $display("FAIL t%0d reserved nonzero", n); errors=errors+1; end
        end
    endtask

    localparam [FRAME_BITS-1:0] A = 256'hC000020A_C6336414_100001BB_061805DC_00000000000000000000000000000000;
    localparam [FRAME_BITS-1:0] B = 256'hCB007105_C00002C8_0016C738_11000040_00000000000000000000000000000000;

    reg [FRAME_BITS-1:0] r1, r2, r3;

    initial begin
        #40 btnC = 1'b0;          // release reset
        @(posedge clk);

        send_frame(A, r1);        // transfer 1: no prior frame -> magic 0x00
        send_frame(B, r2);        // transfer 2: verdict for frame 1 (seq=1)
        send_frame(A, r3);        // transfer 3: verdict for frame 2 (seq=2)

        // transfer 1: "no verdict yet" -> magic must not be 0xA5 (it's 0x00, all reserved 0)
        if (r1[FRAME_BITS-1 -: 8] === 8'hA5) begin $display("FAIL t1: magic 0xA5 but no prior frame"); errors=errors+1; end
        if (r1 !== {FRAME_BITS{1'b0}}) begin $display("FAIL t1: expected all-zero, got %h", r1); errors=errors+1; end

        check_verdict(2, r2, 8'hA5, 8'h00, 8'h00, 8'h00, 8'h01);   // frame 1 (A) clean
        check_verdict(3, r3, 8'hA5, 8'h01, 8'h03, 8'h01, 8'h02);   // frame 2 (B) bloom hit

        if (errors == 0) $display("PASS: nids_top round-trip, pipelined verdicts (clean + bloom hit)");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
