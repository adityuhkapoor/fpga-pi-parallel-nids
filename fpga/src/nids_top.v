`timescale 1ns/1ps
// Bring-up top: SPI slave with frame-pipelined echo. Each received 20-byte frame is
// returned on MISO during the next transfer (the seam where the v2 verdict will go).
// LEDs count received frames as a standalone "frames arriving" indicator.
module nids_top (
    input  wire        clk,    // 100 MHz
    input  wire        btnC,   // reset
    input  wire        sclk,
    input  wire        cs_n,
    input  wire        mosi,
    output wire        miso,
    output reg  [15:0] led
);
    localparam FRAME_BYTES = 20;
    localparam FRAME_BITS  = FRAME_BYTES*8;

    wire                  rst = btnC;
    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    reg [FRAME_BITS-1:0] echo_reg;
    always @(posedge clk) begin
        if (rst)                 echo_reg <= {FRAME_BITS{1'b0}};
        else if (rx_frame_valid) echo_reg <= rx_frame;
    end

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(echo_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );

    always @(posedge clk) begin
        if (rst)                 led <= 16'd0;
        else if (rx_frame_valid) led <= led + 16'd1;
    end
endmodule
