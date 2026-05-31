`timescale 1ns/1ps
// Parallel classifier block: bloom (C2-IP, stateless) + flow_table (per-source state, v2
// step 3 — replaces v1's scan_rate undercounting) + rule_lookup (runtime block-rules, v2
// step 4). All three start on fields_valid and finish independently; classify_valid pulses
// once ALL THREE have produced their result for the packet.
// hit_mask = {rule_match, rate, port_scan, bloom}; severity = max of classifier (bloom 3,
// scan/rate 2) and rule.severity (low 2 bits); escalate = any classifier bit | rule.action[2].
module classifiers (
    input  wire        clk,
    input  wire        rst,
    input  wire [31:0] src_ip, dst_ip,
    input  wire [15:0] src_port, dst_port,
    input  wire [7:0]  proto, tcp_flags,
    input  wire [15:0] pkt_size,
    input  wire [15:0] frame_count,
    input  wire        fields_valid,
    // step-2 passthroughs (driven by nids_top from opcode router / thresholds reg file)
    input  wire [15:0] port_thresh, host_thresh, rate_thresh,
    input  wire [11:0] bf_w_addr, bf_r_addr,
    input  wire [15:0] bf_w_data,
    input  wire        bf_w_en, bf_r_en,
    output wire [15:0] bf_r_data,
    // step-4 rule_lookup: connects through nids_top to rule_store r-port
    input  wire [7:0]  current_rule_epoch,
    output wire [8:0]  rs_r_idx,
    input  wire [71:0] rs_r_rule,
    output reg  [3:0]  hit_mask,        // bit0 bloom, bit1 port-scan, bit2 rate, bit3 rule (v2)
    output reg  [1:0]  severity,
    output reg         escalate,
    output reg         classify_valid
);
    wire bloom_hit, bloom_valid;
    bloom_filter u_bloom (
        .clk(clk), .rst(rst), .src_ip(src_ip), .dst_ip(dst_ip),
        .in_valid(fields_valid), .bloom_hit(bloom_hit), .out_valid(bloom_valid),
        .w_addr(bf_w_addr), .w_data(bf_w_data), .w_en(bf_w_en),
        .r_addr(bf_r_addr), .r_en(bf_r_en),   .r_data(bf_r_data)
    );

    wire ps_hit, rate_hit, ft_valid;
    flow_table u_ft (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .dst_ip(dst_ip), .dst_port(dst_port),
        .proto(proto), .tcp_flags(tcp_flags),
        .pkt_size(pkt_size), .frame_count(frame_count),
        .port_thresh(port_thresh), .host_thresh(host_thresh), .rate_thresh(rate_thresh),
        .in_valid(fields_valid),
        .port_scan_hit(ps_hit), .rate_hit(rate_hit), .out_valid(ft_valid)
    );

    wire        rl_match, rl_valid;
    wire [7:0]  rl_action;
    wire [3:0]  rl_severity;
    rule_lookup u_rl (
        .clk(clk), .rst(rst),
        .src_ip(src_ip), .in_valid(fields_valid),
        .current_rule_epoch(current_rule_epoch),
        .rs_r_idx(rs_r_idx), .rs_r_rule(rs_r_rule),
        .match(rl_match), .out_valid(rl_valid),
        .action(rl_action), .severity(rl_severity)
    );

    // Wait for all three stages; latch results, combine.
    reg bloom_done, ft_done, rl_done;
    reg bh_l, ps_l, rate_l, rm_l;
    reg [7:0] ract_l;
    reg [3:0] rsev_l;
    always @(posedge clk) begin
        classify_valid <= 1'b0;
        if (rst) begin
            bloom_done <= 1'b0; ft_done <= 1'b0; rl_done <= 1'b0;
            hit_mask <= 4'd0; severity <= 2'd0; escalate <= 1'b0;
        end else begin
            if (fields_valid) begin bloom_done <= 1'b0; ft_done <= 1'b0; rl_done <= 1'b0; end
            if (bloom_valid) begin bloom_done <= 1'b1; bh_l   <= bloom_hit;                end
            if (ft_valid)    begin ft_done    <= 1'b1; ps_l   <= ps_hit; rate_l <= rate_hit; end
            if (rl_valid)    begin rl_done    <= 1'b1; rm_l   <= rl_match;
                                   ract_l <= rl_action; rsev_l <= rl_severity;             end
            if (bloom_done && ft_done && rl_done) begin
                hit_mask       <= {rm_l, rate_l, ps_l, bh_l};
                // classifier severity: bloom -> 3, scan/rate -> 2, else 0. Then max with
                // rule severity (clamped to 2 bits since the verdict byte holds 0..3).
                severity       <= ((bh_l ? 2'd3 : ((ps_l | rate_l) ? 2'd2 : 2'd0)) > rsev_l[1:0])
                                  ? (bh_l ? 2'd3 : ((ps_l | rate_l) ? 2'd2 : 2'd0))
                                  : rsev_l[1:0];
                escalate       <= bh_l | ps_l | rate_l | rm_l | ract_l[2];
                classify_valid <= 1'b1;
                bloom_done     <= 1'b0; ft_done <= 1'b0; rl_done <= 1'b0;
            end
        end
    end
endmodule
