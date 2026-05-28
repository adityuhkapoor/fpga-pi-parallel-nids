`timescale 1ns/1ps
// SPI slave, full-duplex. Mode 0 (CPOL=0/CPHA=0), MSB-first, 8-bit, CE0-framed:
// one frame is FRAME_BYTES bytes between CS low and CS high. SCLK/CS/MOSI are async
// to clk and oversampled in the clk domain (2-FF sync + edge detect) rather than
// clocked directly. tx_frame is shifted back on MISO during the transfer; it is
// latched at CS assertion, so the caller supplies frame N-1's response while frame N
// is received (frame-pipelined, same timing as the v2 verdict path).
module spi_slave_rx #(
    parameter FRAME_BYTES = 32
)(
    input  wire                     clk,
    input  wire                     rst,
    input  wire                     sclk,
    input  wire                     cs_n,
    input  wire                     mosi,
    input  wire [FRAME_BYTES*8-1:0] tx_frame,
    output reg                      miso,
    output reg  [7:0]               rx_byte,
    output reg                      rx_byte_valid,
    output reg  [4:0]               byte_index,
    output reg  [FRAME_BYTES*8-1:0] rx_frame,
    output reg                      rx_frame_valid
);
    localparam FRAME_BITS = FRAME_BYTES*8;

    reg [1:0] sclk_s, cs_s, mosi_s;
    reg       sclk_q, cs_q;
    always @(posedge clk) begin
        sclk_s <= {sclk_s[0], sclk};
        cs_s   <= {cs_s[0],   cs_n};
        mosi_s <= {mosi_s[0], mosi};
        sclk_q <= sclk_s[1];
        cs_q   <= cs_s[1];
    end
    wire sclk_rise = sclk_s[1] & ~sclk_q;
    wire sclk_fall = ~sclk_s[1] & sclk_q;
    wire cs_active = ~cs_s[1];
    wire cs_fall   = ~cs_s[1] & cs_q;
    wire mosi_bit  = mosi_s[1];

    reg [2:0]            bit_cnt;
    reg [4:0]            byte_cnt;
    reg [7:0]            shift;
    reg [FRAME_BITS-1:0] rx_sr;
    reg [FRAME_BITS-1:0] tx_sr;

    // Receive: sample MOSI on each SCLK rising edge; byte counter resets when CS idle.
    always @(posedge clk) begin
        rx_byte_valid  <= 1'b0;
        rx_frame_valid <= 1'b0;
        if (rst | ~cs_active) begin
            bit_cnt  <= 3'd0;
            byte_cnt <= 5'd0;
        end else if (sclk_rise) begin
            shift <= {shift[6:0], mosi_bit};
            rx_sr <= {rx_sr[FRAME_BITS-2:0], mosi_bit};
            if (bit_cnt == 3'd7) begin
                bit_cnt       <= 3'd0;
                rx_byte       <= {shift[6:0], mosi_bit};
                rx_byte_valid <= 1'b1;
                byte_index    <= byte_cnt;
                if (byte_cnt == FRAME_BYTES-1) begin
                    byte_cnt       <= 5'd0;
                    rx_frame       <= {rx_sr[FRAME_BITS-2:0], mosi_bit};
                    rx_frame_valid <= 1'b1;
                end else begin
                    byte_cnt <= byte_cnt + 5'd1;
                end
            end else begin
                bit_cnt <= bit_cnt + 3'd1;
            end
        end
    end

    // Transmit: present MSB at CS assertion, advance on each SCLK falling edge so the
    // bit is stable across the master's rising-edge sample. MISO idles low between frames.
    always @(posedge clk) begin
        if (rst) begin
            tx_sr <= {FRAME_BITS{1'b0}};
            miso  <= 1'b0;
        end else if (cs_fall) begin
            tx_sr <= tx_frame;
            miso  <= tx_frame[FRAME_BITS-1];
        end else if (cs_active) begin
            if (sclk_fall) begin
                tx_sr <= {tx_sr[FRAME_BITS-2:0], 1'b0};
                miso  <= tx_sr[FRAME_BITS-2];
            end
        end else begin
            miso <= 1'b0;
        end
    end
endmodule
