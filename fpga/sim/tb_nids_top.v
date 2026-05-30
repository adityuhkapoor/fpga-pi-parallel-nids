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

    // Query frame for opcode 0x02 (snapshot). Byte 16 = 0x02; bytes 0-15 don't matter for snapshot.
    // Layout: byte 16 sits at bits [FRAME_BITS-1-128 -: 8] = [127:120] for FRAME_BITS=256.
    localparam [FRAME_BITS-1:0] SNAP_Q =
        256'h0000000000000000_0000000000000000_0200000000000000_0000000000000000;

    // --- step-2 control frames (PROTOCOL.md byte layouts) ---
    // 0x11 threshold write: b0=id=0x02 (RATE_THRESH), b1-2=val=0x000C, byte16=0x11
    localparam [FRAME_BITS-1:0] THR_W =
        256'h02000C0000000000_0000000000000000_1100000000000000_0000000000000000;
    // 0x14 threshold read: b0=id=0x02, byte16=0x14
    localparam [FRAME_BITS-1:0] THR_R =
        256'h0200000000000000_0000000000000000_1400000000000000_0000000000000000;
    // 0x10 bloom write: b0-1=addr=0x0ABC (only low 12 used = 0xABC), b2-3=value=0xBEEF, byte16=0x10
    localparam [FRAME_BITS-1:0] BLM_W =
        256'h0ABCBEEF00000000_0000000000000000_1000000000000000_0000000000000000;
    // 0x13 bloom read: b0-1=addr=0x0ABC, byte16=0x13
    localparam [FRAME_BITS-1:0] BLM_R =
        256'h0ABC000000000000_0000000000000000_1300000000000000_0000000000000000;
    // 0x12 rule write idx=42: b0-1=0x002A, b2-5=src_ip=0xCB007105, b6=action=0x05,
    //                           b7=sev=0x03, b8=epoch=0x07, byte16=0x12
    localparam [FRAME_BITS-1:0] RUL_W =
        256'h002ACB00710505030700000000000000_1200000000000000_0000000000000000;
    // 0x15 rule read idx=42: b0-1=0x002A, byte16=0x15
    localparam [FRAME_BITS-1:0] RUL_R =
        256'h002A000000000000_0000000000000000_1500000000000000_0000000000000000;
    localparam [FRAME_BITS-1:0] FLUSH = {FRAME_BITS{1'b0}};

    reg [FRAME_BITS-1:0] r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13;

    initial begin
        #40 btnC = 1'b0;          // release reset
        @(posedge clk);

        send_frame(A, r1);        // transfer 1: no prior frame -> magic 0x00
        send_frame(B, r2);        // transfer 2: verdict for frame 1 (seq=1)
        send_frame(A, r3);        // transfer 3: verdict for frame 2 (seq=2)

        if (r1[FRAME_BITS-1 -: 8] === 8'hA5) begin $display("FAIL t1: magic 0xA5 but no prior frame"); errors=errors+1; end
        if (r1 !== {FRAME_BITS{1'b0}}) begin $display("FAIL t1: expected all-zero, got %h", r1); errors=errors+1; end

        check_verdict(2, r2, 8'hA5, 8'h00, 8'h00, 8'h00, 8'h01);   // frame 1 (A) clean
        check_verdict(3, r3, 8'hA5, 8'h01, 8'h03, 8'h01, 8'h02);   // frame 2 (B) bloom hit

        // --- opcode 0x02: snapshot query. Send a SNAP_Q frame; r4 returns frame-3's verdict
        // (one-frame lag carries A's verdict for frame 3, seq=3, clean). r5 carries the snapshot
        // response for SNAP_Q -> magic must be 0x5A, distinct from verdict magic 0xA5.
        send_frame(SNAP_Q, r4);
        send_frame({FRAME_BITS{1'b0}}, r5);

        check_verdict(4, r4, 8'hA5, 8'h00, 8'h00, 8'h00, 8'h03);   // frame 3 (A again) clean
        if (r5[FRAME_BITS-1 -: 8] !== 8'h5A) begin
            $display("FAIL snapshot magic %02h != 5A", r5[FRAME_BITS-1 -: 8]); errors=errors+1; end

        // --- step-2: threshold write 0x11 (id=0x02 RATE, val=0x000C), then read back via 0x14 ---
        send_frame(THR_W, r6);
        send_frame(FLUSH, r7);                         // r7 = ack for THR_W
        send_frame(THR_R, r8);
        send_frame(FLUSH, r9);                         // r9 = response for THR_R

        if (r7[FRAME_BITS-1 -: 8] !== 8'h5A || r7[FRAME_BITS-9 -: 8] !== 8'h11) begin
            $display("FAIL thr_w ack: magic=%02h op=%02h",
                     r7[FRAME_BITS-1 -: 8], r7[FRAME_BITS-9 -: 8]); errors=errors+1; end
        if (r9[FRAME_BITS-1 -: 8] !== 8'h5A
            || r9[FRAME_BITS-9 -: 8] !== 8'h02
            || r9[FRAME_BITS-17 -: 16] !== 16'h000C) begin
            $display("FAIL thr_r read-back: magic=%02h id=%02h val=%04h (want 5A 02 000C)",
                     r9[FRAME_BITS-1 -: 8], r9[FRAME_BITS-9 -: 8], r9[FRAME_BITS-17 -: 16]);
            errors=errors+1; end

        // --- step-2: bloom write 0x10 (addr=0xABC, val=0xBEEF), then read back via 0x13 ---
        send_frame(BLM_W, r10);
        send_frame(FLUSH, r11);                        // ack for BLM_W
        send_frame(BLM_R, r12);
        send_frame(FLUSH, r13);                        // response for BLM_R

        if (r11[FRAME_BITS-1 -: 8] !== 8'h5A || r11[FRAME_BITS-9 -: 8] !== 8'h10) begin
            $display("FAIL blm_w ack: magic=%02h op=%02h",
                     r11[FRAME_BITS-1 -: 8], r11[FRAME_BITS-9 -: 8]); errors=errors+1; end
        if (r13[FRAME_BITS-1 -: 8] !== 8'h5A
            || r13[FRAME_BITS-9 -: 16] !== 16'h0ABC
            || r13[FRAME_BITS-25 -: 16] !== 16'hBEEF) begin
            $display("FAIL blm_r read-back: magic=%02h addr=%04h val=%04h (want 5A 0ABC BEEF)",
                     r13[FRAME_BITS-1 -: 8], r13[FRAME_BITS-9 -: 16], r13[FRAME_BITS-25 -: 16]);
            errors=errors+1; end

        if (errors == 0) $display("PASS: nids_top v1.1 + snapshot + step-2 threshold + bloom roundtrips");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
