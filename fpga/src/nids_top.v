`timescale 1ns/1ps
// NIDS pipeline top: spi_slave_rx -> header_parser -> classifiers -> verdict_encoder,
// with the verdict shifted back on MISO one frame later (v2-pipelined, PROTOCOL.md).
// A per-frame counter drives the verdict seq byte and the LED activity display.
// Classifier stages are stubbed (clean verdicts) until the classifier spec is locked.
module nids_top (
    input  wire        clk,    // 100 MHz
    input  wire        btnC,   // reset
    input  wire        sclk,
    input  wire        cs_n,
    input  wire        mosi,
    output wire        miso,
    output wire [15:0] led
);
    localparam FRAME_BYTES = 32;
    localparam FRAME_BITS  = FRAME_BYTES*8;

    wire rst = btnC;

    wire [FRAME_BITS-1:0] rx_frame;
    wire                  rx_frame_valid;

    // Frame counter: incremented once per received frame. seq for frame K is K & 0xFF,
    // captured when the frame arrives and held while the pipeline produces its verdict.
    reg [15:0] frame_count;
    reg [15:0] frame_idx;   // 0-based index of the current frame (pre-increment value)
    reg [7:0]  seq_reg;
    always @(posedge clk) begin
        if (rst) begin
            frame_count <= 16'd0;
            frame_idx   <= 16'd0;
            seq_reg     <= 8'd0;
        end else if (rx_frame_valid) begin
            frame_idx   <= frame_count;               // index of THIS frame, drives the window epoch
            frame_count <= frame_count + 16'd1;
            seq_reg     <= frame_count[7:0] + 8'd1;   // K & 0xFF for this frame
        end
    end
    assign led = frame_count;

    wire [31:0] src_ip, dst_ip;
    wire [15:0] src_port, dst_port, pkt_size;
    wire [7:0]  proto, tcp_flags;
    wire        fields_valid;

    header_parser #(.FRAME_BYTES(FRAME_BYTES)) u_parser (
        .clk(clk), .rst(rst), .frame(rx_frame), .frame_valid(rx_frame_valid),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size), .fields_valid(fields_valid)
    );

    wire [2:0] hit_mask;
    wire [1:0] severity;
    wire       escalate, classify_valid;

    classifiers u_cls (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .src_port(src_port), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags), .pkt_size(pkt_size),
        .frame_count(frame_idx), .fields_valid(fields_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .classify_valid(classify_valid)
    );

    wire [FRAME_BITS-1:0] verdict_frame;
    wire                  verdict_valid;

    verdict_encoder #(.FRAME_BYTES(FRAME_BYTES)) u_venc (
        .clk(clk), .rst(rst), .classify_valid(classify_valid),
        .hit_mask(hit_mask), .severity(severity), .escalate(escalate), .seq(seq_reg),
        .verdict_frame(verdict_frame), .verdict_valid(verdict_valid)
    );

    // Hold the latest verdict; spi_slave_rx loads it at CS assertion so it ships during
    // the next transfer (the one-frame lag). Resets to 0 -> magic=0x00 until a real verdict.
    reg [FRAME_BITS-1:0] verdict_reg;
    always @(posedge clk) begin
        if (rst)               verdict_reg <= {FRAME_BITS{1'b0}};
        else if (verdict_valid) verdict_reg <= verdict_frame;
    end

    spi_slave_rx #(.FRAME_BYTES(FRAME_BYTES)) u_spi (
        .clk(clk), .rst(rst), .sclk(sclk), .cs_n(cs_n), .mosi(mosi),
        .tx_frame(verdict_reg), .miso(miso),
        .rx_byte(), .rx_byte_valid(), .byte_index(),
        .rx_frame(rx_frame), .rx_frame_valid(rx_frame_valid)
    );
endmodule
