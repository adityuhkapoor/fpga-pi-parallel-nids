`timescale 1ns/1ps
// Drives a mode-0 MSB-first SPI master against spi_slave_rx and checks:
//   - bytes deserialize correctly (rx_frame == sent frame)
//   - MISO returns the previous frame (frame-pipelined echo): frame N's data comes
//     back during frame N+1; the first frame returns zeros.
// Golden vectors use RFC5737 documentation addresses (not real traffic).
module tb_spi_slave_rx;
    localparam FRAME_BYTES = 32;
    localparam FRAME_BITS  = FRAME_BYTES*8;
    integer    HALF        = 250;   // SCLK half-period (ns); 250 -> 2 MHz, ~50x oversampled

    reg clk = 1'b0, rst = 1'b1;
    reg sclk = 1'b0, cs_n = 1'b1, mosi = 1'b0;
    wire miso;
    wire [7:0]            rx_byte;
    wire                  rx_byte_valid;
    wire [4:0]            byte_index;
    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    // Frame-pipelined echo source: latch each received frame, send it back next frame.
    reg [FRAME_BITS-1:0] echo_reg = {FRAME_BITS{1'b0}};
    always @(posedge clk) if (rx_frame_valid) echo_reg <= rx_frame;

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) dut (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(echo_reg), .miso(miso),
        .rx_byte(rx_byte), .rx_byte_valid(rx_byte_valid), .byte_index(byte_index),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );

    always #5 clk = ~clk;   // 100 MHz

    integer frame_valid_count = 0;
    always @(posedge clk) if (rx_frame_valid) frame_valid_count = frame_valid_count + 1;

    task send_byte(input [7:0] tx, output [7:0] rx);
        integer i;
        begin
            for (i = 7; i >= 0; i = i - 1) begin
                mosi = tx[i];
                #HALF sclk = 1'b1;          // rising: slave samples MOSI, master samples MISO
                #(HALF/2) rx[i] = miso;
                #(HALF/2) sclk = 1'b0;       // falling: slave advances MISO
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
            #HALF cs_n = 1'b1;               // CS high: frame end
            #(HALF*4);
        end
    endtask

    // src 192.0.2.10  dst 198.51.100.20  sport 4096 dport 443 proto TCP flags PSH|ACK size 1500
    localparam [FRAME_BITS-1:0] A = 256'hC000020A_C6336414_100001BB_061805DC_00000000000000000000000000000000;
    // src 203.0.113.5 dst 192.0.2.200  sport 22   dport 51000 proto UDP flags 0 size 64
    localparam [FRAME_BITS-1:0] B = 256'hCB007105_C00002C8_0016C738_11000040_00000000000000000000000000000000;

    integer errors = 0;
    reg [FRAME_BITS-1:0] e1, e2, e3, e4;

    task expect_eq(input [FRAME_BITS-1:0] got, input [FRAME_BITS-1:0] exp, input [127:0] tag);
        begin
            if (got !== exp) begin
                $display("FAIL [%0s]: got %h exp %h", tag, got, exp);
                errors = errors + 1;
            end
        end
    endtask

    initial begin
        #100 rst = 1'b0;
        #100;
        send_frame(A, e1);
        expect_eq(rx_frame, A, "rx1");      // frame 1 deserialized
        expect_eq(e1, {FRAME_BITS{1'b0}}, "echo1");  // first echo is zeros
        send_frame(B, e2);
        expect_eq(rx_frame, B, "rx2");
        expect_eq(e2, A, "echo2");          // frame 2 echo == frame 1
        send_frame(A, e3);
        expect_eq(rx_frame, A, "rx3");
        expect_eq(e3, B, "echo3");          // frame 3 echo == frame 2

        if (frame_valid_count !== 3) begin
            $display("FAIL: rx_frame_valid pulsed %0d times, expected 3", frame_valid_count);
            errors = errors + 1;
        end

        // Elevated-rate logic check at HALF=34ns (~14.7 MHz). xsim has no SI/metastability
        // model, so this proves the deserialize logic, not the silicon ceiling (spi_ber_ramp.py).
        HALF = 34;
        send_frame(A, e4);
        expect_eq(rx_frame, A, "rx_fast");   // deserialize correct at the faster clock

        if (errors == 0) $display("PASS: spi_slave_rx deserialize + frame-pipelined echo");
        else             $display("FAIL: %0d error(s)", errors);
        $finish;
    end
endmodule
