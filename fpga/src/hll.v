`timescale 1ns/1ps
// HyperLogLog over src_ip: 2048 registers x {epoch[3:0],rank[4:0]}. fmix32 finalizer
// (two registered multiplies) gives the avalanche HLL needs; top 11 bits -> bucket,
// low 21 -> rank (leftmost-1, 1-based). Maintains the SCALED harmonic sum S = sum 2^(32-rank)
// (rank 0 -> 2^32) and the zero-register count, both read by the Pi to finish the estimate.
// Lazy 4-bit epoch reset on win_tick. Bit-exact twin: hll.py.
module hll #(parameter M = 2048, parameter IDXB = 11, parameter RB = 21) (
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip,
    input  wire        upd_valid,
    input  wire        win_tick,
    input  wire        q_valid,            // pulse: latch harmonic_sum + zeros to outputs
    output reg  [47:0] harmonic_sum,
    output reg  [11:0] zeros,
    output reg         q_done
);
    localparam [31:0] C1 = 32'h85EBCA6B, C2 = 32'hC2B2AE35;
    localparam [47:0] INIT = 48'd2048 * 48'h100000000;   // m * 2^32 = 2^43

    (* ram_style="block" *) reg [8:0] mem[0:M-1];        // {epoch[3:0], rank[4:0]}
    integer k;
    initial begin
        for (k=0;k<M;k=k+1) mem[k]=9'd0;
        harmonic_sum = INIT; zeros = 12'd2048; q_done = 1'b0;
    end

    reg [3:0]  cur_epoch = 4'd0;

    function [4:0] rank21(input [RB-1:0] w);
        integer i; reg found;
        begin rank21 = RB[4:0] + 5'd1; found = 1'b0;     // w==0 -> RB+1 (=22)
            for (i=RB-1;i>=0;i=i-1)
                if (!found && w[i]) begin rank21 = (RB-1-i) + 1; found = 1'b1; end
        end
    endfunction
    function [47:0] term(input [4:0] m);                 // 2^(32-rank), rank in [0,22] -> <=2^32
        term = 48'd1 << (6'd32 - {1'b0,m});
    endfunction

    reg [2:0]         phase;
    reg [31:0]        m1, m2;                             // pipelined fmix multiply outputs
    reg [IDXB-1:0]    bkt;
    reg [4:0]         rnk, old;
    reg [8:0]         rword;

    always @(posedge clk) rword <= mem[bkt];             // synchronous read

    always @(posedge clk) begin
        q_done <= 1'b0;
        if (rst) begin
            phase <= 3'd0; cur_epoch <= 4'd0; harmonic_sum <= INIT; zeros <= 12'd2048;
        end else begin
            if (win_tick) begin
                cur_epoch    <= cur_epoch + 4'd1;        // lazy reset of registers
                harmonic_sum <= INIT;
                zeros        <= 12'd2048;
            end
            case (phase)
                3'd0: if (upd_valid) begin
                          m1 <= (src_ip ^ (src_ip >> 16)) * C1;   // fmix step 1 (registered)
                          phase <= 3'd1;
                      end else if (q_valid) begin
                          q_done <= 1'b1; phase <= 3'd0;          // outputs already hold S, zeros
                      end
                3'd1: begin m2 <= (m1 ^ (m1 >> 13)) * C2; phase <= 3'd2; end   // fmix step 2
                3'd2: begin
                          // h = m2 ^ (m2>>16); split into bucket + rank
                          bkt <= (m2 ^ (m2 >> 16)) >> (32 - IDXB);
                          rnk <= rank21((m2 ^ (m2 >> 16)) & ((1 << RB) - 1));
                          phase <= 3'd3;
                      end
                3'd3: phase <= 3'd4;                                // read latency for rword
                3'd4: begin
                          old = (rword[8:5] == cur_epoch) ? rword[4:0] : 5'd0;
                          if (rnk > old) begin
                              if (old == 5'd0) zeros <= zeros - 12'd1;
                              harmonic_sum <= harmonic_sum + term(rnk) - term(old);
                              mem[bkt] <= {cur_epoch, rnk};
                          end
                          phase <= 3'd0;
                      end
                default: phase <= 3'd0;
            endcase
        end
    end
endmodule
