`timescale 1ns/1ps
// v2 step 3: per-source state table replacing scan_rate.v's 256-bucket undercounting.
// 4096 buckets × 114b cells; fingerprint (16b from a DIFFERENT multiplier) detects collisions
// so a colliding source EVICTS instead of silently merging. Bit-exact twin: flow_table_model.py.
// 4-phase FSM mirrors scan_rate (DSP multiplies isolated in phase 0; popcount + threshold
// compare in phase 3 off the BRAM-read+RMW path) -- timing-closure shape proven by v1.1.
// Cell layout (high->low, total 114b): fp:16 | epoch:4 | pkt_count:14 | byte_count:24 |
//   syn_count:12 | dport_fp:16 | dhost_fp:16 | flags:8 | reserved:4
module flow_table (
    input  wire        clk, rst,
    input  wire [31:0] src_ip, dst_ip,
    input  wire [15:0] dst_port,
    input  wire [7:0]  proto, tcp_flags,
    input  wire [15:0] pkt_size, frame_count,
    input  wire [15:0] port_thresh, host_thresh, rate_thresh,
    input  wire        in_valid,
    output reg         port_scan_hit, rate_hit, out_valid
);
    localparam [31:0] A1 = 32'h9E3779B1, A2 = 32'h85EBCA77;
    localparam [13:0] PKT_MAX  = 14'h3FFF;
    localparam [23:0] BYTE_MAX = 24'hFFFFFF;
    localparam [11:0] SYN_MAX  = 12'hFFF;

    function [11:0] f_bucket(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A1; f_bucket = p[31:20]; end
    endfunction
    function [15:0] f_fp(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A2; f_fp = p[27:12]; end
    endfunction
    function [3:0]  f_portbit(input [15:0] dp);
        reg [63:0] p; begin p = {48'd0, dp} * A2; f_portbit = p[31:28]; end
    endfunction
    function [3:0]  f_hostbit(input [31:0] ip);
        reg [63:0] p; begin p = {32'd0, ip} * A1; f_hostbit = p[31:28]; end
    endfunction
    function [4:0]  popcnt16(input [15:0] v);
        integer k; begin
            popcnt16 = 5'd0;
            for (k = 0; k < 16; k = k + 1) popcnt16 = popcnt16 + {4'd0, v[k]};
        end
    endfunction

    (* ram_style="block" *) reg [113:0] mem [0:4095];
    integer j;
    initial begin
        for (j = 0; j < 4096; j = j + 1) mem[j] = 114'd0;
        port_scan_hit = 1'b0; rate_hit = 1'b0; out_valid = 1'b0;
    end

    wire [3:0] cur_epoch = frame_count[7:4];
    wire       syn_gate  = (proto == 8'd6) & tcp_flags[1] & ~tcp_flags[4];

    reg [1:0]   phase;
    reg [11:0]  addr;
    reg [15:0]  l_fp, l_pkt_size_lo;
    reg [3:0]   l_pbit, l_hbit, l_epoch;
    reg [7:0]   l_flags;
    reg [23:0]  l_pkt_size;       // zero-extended for byte accumulator
    reg         l_syn;
    reg [113:0] rdata;
    // phase-2 RMW outputs latched -> phase 3
    reg [15:0]  s_pfp, s_hfp;
    reg [13:0]  s_cnt;
    // phase-2 unpack + RMW scratch (declared at module scope; Verilog-2001 doesn't allow
    // reg decls inside unnamed begin/end blocks)
    reg [15:0]  e_fp, e_pfp, e_hfp, n_pfp, n_hfp;
    reg [3:0]   e_ep;
    reg [13:0]  e_pcnt, n_pcnt;
    reg [23:0]  e_bcnt, n_bcnt;
    reg [11:0]  e_scnt, n_scnt;
    reg [7:0]   e_flags, n_flags;

    always @(posedge clk) rdata <= mem[addr];      // synchronous read

    always @(posedge clk) begin
        out_valid <= 1'b0;
        if (rst) begin
            phase <= 2'd0; port_scan_hit <= 1'b0; rate_hit <= 1'b0;
        end else case (phase)
            2'd0: if (in_valid) begin
                      addr        <= f_bucket(src_ip);
                      l_fp        <= f_fp(src_ip);
                      l_pbit      <= f_portbit(dst_port);
                      l_hbit      <= f_hostbit(dst_ip);
                      l_epoch     <= cur_epoch;
                      l_syn       <= syn_gate;
                      l_flags     <= tcp_flags;
                      l_pkt_size  <= {8'd0, pkt_size};
                      phase       <= 2'd1;
                  end
            2'd1: phase <= 2'd2;
            2'd2: begin
                      // Unpack cell (or treat as blank if fp/epoch mismatch).
                      e_fp    = rdata[113:98];
                      e_ep    = rdata[97:94];
                      e_pcnt  = rdata[93:80];
                      e_bcnt  = rdata[79:56];
                      e_scnt  = rdata[55:44];
                      e_pfp   = rdata[43:28];
                      e_hfp   = rdata[27:12];
                      e_flags = rdata[11:4];
                      if (e_fp != l_fp || e_ep != l_epoch) begin
                          e_pcnt = 14'd0; e_bcnt = 24'd0; e_scnt = 12'd0;
                          e_pfp = 16'd0;  e_hfp = 16'd0;  e_flags = 8'd0;
                      end
                      n_pcnt  = (e_pcnt == PKT_MAX)  ? PKT_MAX  : (e_pcnt + 14'd1);
                      n_bcnt  = (e_bcnt + l_pkt_size > BYTE_MAX) ? BYTE_MAX : (e_bcnt + l_pkt_size);
                      n_scnt  = l_syn ? ((e_scnt == SYN_MAX) ? SYN_MAX : (e_scnt + 12'd1)) : e_scnt;
                      n_pfp   = l_syn ? (e_pfp | (16'd1 << l_pbit)) : e_pfp;
                      n_hfp   = l_syn ? (e_hfp | (16'd1 << l_hbit)) : e_hfp;
                      n_flags = e_flags | l_flags;
                      mem[addr] <= {l_fp, l_epoch, n_pcnt, n_bcnt, n_scnt, n_pfp, n_hfp, n_flags, 4'd0};
                      s_pfp <= n_pfp; s_hfp <= n_hfp; s_cnt <= n_pcnt;
                      phase <= 2'd3;
                  end
            2'd3: begin
                      port_scan_hit <= ({11'd0, popcnt16(s_pfp)} >= port_thresh) |
                                       ({11'd0, popcnt16(s_hfp)} >= host_thresh);
                      rate_hit      <= ({2'd0,  s_cnt}           >= rate_thresh);
                      out_valid     <= 1'b1;
                      phase         <= 2'd0;
                  end
        endcase
    end
endmodule
