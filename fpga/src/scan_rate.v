`timescale 1ns/1ps
// Stateful per-source classifier: port-scan (vertical + horizontal) + rate-anomaly.
// One read-modify-write per packet against a 256-entry BRAM (CLASSIFIER.md v1.1), the
// bit-exact mirror of scan_rate.py.
//
// Entry[63:0] = { rsvd[19:0], epoch[3:0], host_fp[15:0], port_fp[15:0], pkt_count[7:0] }
//   pkt_count = [7:0], port_fp = [23:8], host_fp = [39:24], epoch = [43:40].
// Window = 16 frames (epoch = frame_count[7:4]); lazy tumbling reset clears a source's
// entry whenever its stored epoch != the current epoch, before applying the packet.
//
// Multiply-shift hashes (low-32 of the product, then the top bits): bucket = (src*A1)>>24,
// port_bit = (dst_port*A2)>>28, host_bit = (dst_ip*A1)>>28. Distinct ports/hosts set bits
// in the fingerprints; popcount approximates the distinct count (collisions undercount).
//
// 4-phase RMW so each cycle's logic meets 100 MHz: the DSP multiplies are isolated in
// phase 0 (registered), and the popcount/threshold compare gets its own phase 3 instead
// of hanging off the multiply. Frame period (>150us) >> 4 cycles, so a source never
// collides with itself in flight -> no read-after-write forwarding needed.
module scan_rate (
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] dst_port,
    input  wire [7:0]  proto,
    input  wire [7:0]  tcp_flags,
    input  wire [15:0] frame_count,
    input  wire        in_valid,
    output reg         port_scan_hit,
    output reg         rate_hit,
    output reg         out_valid
);
    localparam [31:0] A1 = 32'h9E3779B1, A2 = 32'h85EBCA77;
    localparam integer PORT_THRESH = 5, HOST_THRESH = 5, RATE_THRESH = 8;

    function [7:0] h_bucket(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A1; h_bucket = p[31:24]; end
    endfunction
    function [3:0] h_portbit(input [15:0] dp);
        reg [63:0] p; begin p = {48'd0, dp} * A2; h_portbit = p[31:28]; end
    endfunction
    function [3:0] h_hostbit(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A1; h_hostbit = p[31:28]; end
    endfunction
    function [4:0] popcnt16(input [15:0] v);
        integer k; begin
            popcnt16 = 5'd0;
            for (k = 0; k < 16; k = k + 1) popcnt16 = popcnt16 + {4'd0, v[k]};
        end
    endfunction

    (* ram_style = "block" *) reg [63:0] mem [0:255];
    integer j;
    initial begin
        for (j = 0; j < 256; j = j + 1) mem[j] = 64'd0;
        port_scan_hit = 1'b0; rate_hit = 1'b0; out_valid = 1'b0;
    end

    wire [3:0] cur_epoch = frame_count[7:4];                 // (frame_count >> 4) & 0xF
    wire       syn_gate  = (proto == 8'd6) & tcp_flags[1] & ~tcp_flags[4];  // TCP SYN, no ACK

    reg [1:0]  phase;
    reg [7:0]  addr;
    reg [63:0] rdata;
    reg        l_syn;
    reg [3:0]  l_epoch, l_pbit, l_hbit;     // hashes registered in phase 0 (DSP off the hot path)
    // phase-2 scratch (blocking) and phase-2 -> phase-3 registers
    reg [3:0]  e_epoch;
    reg [15:0] e_pfp, e_hfp, n_pfp, n_hfp;
    reg [7:0]  e_cnt, n_cnt;
    reg [15:0] s_pfp, s_hfp;
    reg [7:0]  s_cnt;

    always @(posedge clk) rdata <= mem[addr];                // synchronous BRAM read (1-cycle latency)

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            phase <= 2'd0; port_scan_hit <= 1'b0; rate_hit <= 1'b0;
        end else case (phase)
            2'd0: if (in_valid) begin                        // latch + issue read; register the hashes
                      addr    <= h_bucket(src_ip);
                      l_pbit  <= h_portbit(dst_port);
                      l_hbit  <= h_hostbit(dst_ip);
                      l_syn   <= syn_gate;
                      l_epoch <= cur_epoch;
                      phase   <= 2'd1;
                  end
            2'd1: phase <= 2'd2;                             // wait one cycle for read latency
            2'd2: begin                                      // rdata valid: unpack, reset, update, write
                      e_cnt   = rdata[7:0];
                      e_pfp   = rdata[23:8];
                      e_hfp   = rdata[39:24];
                      e_epoch = rdata[43:40];
                      if (e_epoch != l_epoch) begin          // lazy tumbling reset
                          e_pfp = 16'd0; e_hfp = 16'd0; e_cnt = 8'd0;
                      end
                      n_cnt = (e_cnt == 8'hFF) ? 8'hFF : (e_cnt + 8'd1);
                      n_pfp = l_syn ? (e_pfp | (16'd1 << l_pbit)) : e_pfp;
                      n_hfp = l_syn ? (e_hfp | (16'd1 << l_hbit)) : e_hfp;
                      s_cnt <= n_cnt; s_pfp <= n_pfp; s_hfp <= n_hfp;     // -> phase 3 popcount
                      mem[addr] <= {20'd0, l_epoch, n_hfp, n_pfp, n_cnt}; // write back
                      phase <= 2'd3;
                  end
            2'd3: begin                                      // popcount + thresholds (own cycle)
                      port_scan_hit <= (popcnt16(s_pfp) >= PORT_THRESH) |
                                       (popcnt16(s_hfp) >= HOST_THRESH);
                      rate_hit      <= (s_cnt >= RATE_THRESH);
                      out_valid     <= 1'b1;
                      phase         <= 2'd0;
                  end
        endcase
    end
endmodule
