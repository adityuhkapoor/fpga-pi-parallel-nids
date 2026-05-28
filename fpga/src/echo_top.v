`timescale 1ns/1ps
// BER instrument: spi_slave_rx in pure frame-echo mode (tx_frame = last rx_frame),
// the delay-1 echo spi_ber_ramp.py checks. No classifier -- isolates the link only,
// so every received bit must round-trip and any link error shows up immediately.
module echo_top (
    input  wire        clk,    // 100 MHz
    input  wire        btnC,   // reset
    input  wire        sclk,
    input  wire        cs_n,
    input  wire        mosi,
    output wire        miso,
    output wire [15:0] led
);
    localparam FRAME_BYTES = 32;          // BER ramp link-only test (frame width irrelevant to SI)
    localparam FRAME_BITS  = FRAME_BYTES*8;
    wire rst = btnC;

    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    reg [FRAME_BITS-1:0] echo_reg;
    reg [15:0]           frame_count;
    always @(posedge clk) begin
        if (rst) begin
            echo_reg    <= {FRAME_BITS{1'b0}};
            frame_count <= 16'd0;
        end else if (rx_frame_valid) begin
            echo_reg    <= rx_frame;
            frame_count <= frame_count + 16'd1;
        end
    end
    assign led = frame_count;

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(echo_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );
endmodule
