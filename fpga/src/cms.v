`timescale 1ns/1ps
// Count-Min sketch: 5 independent banks (4096 x {epoch[3:0],count[13:0]}), key = src_ip,
// +1 per packet, point-query = min over banks. Lazy 4-bit epoch reset on win_tick (a cell
// whose stored epoch != cur_epoch reads as 0, overwritten on next touch). Bit-exact twin:
// cms.py. The 5 multiply-shift hashes are registered in phase 0 to keep the DSP off the
// read-modify-write path (100 MHz closure, same trick as scan_rate.v). One op (update OR
// query) at a time; the frame period (>=2.7us @8MHz) dwarfs the 4-cycle op, so no overlap.
module cms #(parameter COLS = 4096, parameter CW = 14) (
    input  wire          clk,
    input  wire          rst,
    input  wire [31:0]   src_ip,
    input  wire          upd_valid,    // pulse: +1 this src across all 5 banks
    input  wire          win_tick,     // pulse: advance epoch (lazy reset)
    input  wire [31:0]   q_ip,
    input  wire          q_valid,      // pulse: point-query
    output reg  [CW-1:0] q_count,
    output reg           q_done,
    output reg  [CW-1:0] upd_count,    // post-update min-count of the updated src (for top-1)
    output reg           upd_done
);
    localparam COLB = 12;              // log2(COLS)
    localparam [13:0] CMAX = 14'h3FFF;
    localparam [31:0] A0=32'h9E3779B1, A1=32'h85EBCA77, A2=32'hC2B2AE3D,
                      A3=32'h27D4EB2F, A4=32'h165667B1;

    (* ram_style="block" *) reg [17:0] mem0[0:COLS-1];
    (* ram_style="block" *) reg [17:0] mem1[0:COLS-1];
    (* ram_style="block" *) reg [17:0] mem2[0:COLS-1];
    (* ram_style="block" *) reg [17:0] mem3[0:COLS-1];
    (* ram_style="block" *) reg [17:0] mem4[0:COLS-1];
    integer k;
    initial begin
        for (k=0;k<COLS;k=k+1) begin mem0[k]=0;mem1[k]=0;mem2[k]=0;mem3[k]=0;mem4[k]=0; end
        q_count=0; q_done=0; upd_count=0; upd_done=0;
    end

    reg [3:0] cur_epoch = 4'd0;

    function [COLB-1:0] col(input [31:0] ip, input [31:0] a);
        reg [63:0] p; begin p = ip * a; col = p[31:20]; end   // top 12 of low-32 product
    endfunction

    reg [1:0]      phase;
    reg            is_upd;
    reg [COLB-1:0] c0,c1,c2,c3,c4;     // registered columns (phase 0)
    reg [17:0]     r0,r1,r2,r3,r4;     // synchronous read data
    reg [13:0]     s0,s1,s2,s3,s4;     // phase-2 -> phase-3 scratch (post-RMW counts or eff values)

    // synchronous BRAM reads at the registered columns
    always @(posedge clk) begin
        r0 <= mem0[c0]; r1 <= mem1[c1]; r2 <= mem2[c2]; r3 <= mem3[c3]; r4 <= mem4[c4];
    end

    // effective count of a read word under lazy epoch
    function [13:0] eff(input [17:0] word);
        eff = (word[17:14] == cur_epoch) ? word[13:0] : 14'd0;
    endfunction
    function [13:0] inc(input [13:0] v);
        inc = (v == CMAX) ? CMAX : (v + 14'd1);
    endfunction
    function [13:0] min2(input [13:0] a, input [13:0] b); min2 = (a<b)?a:b; endfunction

    always @(posedge clk) begin
        q_done <= 1'b0; upd_done <= 1'b0;
        if (rst) begin
            phase <= 2'd0; cur_epoch <= 4'd0; q_count <= {CW{1'b0}};
        end else begin
            if (win_tick) cur_epoch <= cur_epoch + 4'd1;   // lazy reset
            case (phase)
                2'd0: if (upd_valid | q_valid) begin
                          is_upd <= upd_valid;
                          c0 <= col(upd_valid?src_ip:q_ip, A0);
                          c1 <= col(upd_valid?src_ip:q_ip, A1);
                          c2 <= col(upd_valid?src_ip:q_ip, A2);
                          c3 <= col(upd_valid?src_ip:q_ip, A3);
                          c4 <= col(upd_valid?src_ip:q_ip, A4);
                          phase <= 2'd1;
                      end
                2'd1: phase <= 2'd2;                        // read latency
                2'd2: begin
                          // RMW the BRAMs AND register the 5 post-update / eff values; defer the
                          // 5-way min tree to phase 3 to keep it off the BRAM-read+inc+min path.
                          if (is_upd) begin
                              mem0[c0] <= {cur_epoch, inc(eff(r0))};
                              mem1[c1] <= {cur_epoch, inc(eff(r1))};
                              mem2[c2] <= {cur_epoch, inc(eff(r2))};
                              mem3[c3] <= {cur_epoch, inc(eff(r3))};
                              mem4[c4] <= {cur_epoch, inc(eff(r4))};
                              s0 <= inc(eff(r0)); s1 <= inc(eff(r1)); s2 <= inc(eff(r2));
                              s3 <= inc(eff(r3)); s4 <= inc(eff(r4));
                          end else begin
                              s0 <= eff(r0); s1 <= eff(r1); s2 <= eff(r2);
                              s3 <= eff(r3); s4 <= eff(r4);
                          end
                          phase <= 2'd3;
                      end
                2'd3: begin
                          if (is_upd) begin
                              upd_count <= min2(min2(min2(s0,s1),min2(s2,s3)),s4);
                              upd_done  <= 1'b1;
                          end else begin
                              q_count <= min2(min2(min2(s0,s1),min2(s2,s3)),s4);
                              q_done  <= 1'b1;
                          end
                          phase <= 2'd0;
                      end
                default: phase <= 2'd0;
            endcase
        end
    end
endmodule
