# Compile and run the FPGA testbenches headless; errors if any doesn't PASS.
#   vivado -mode batch -source run_sim.tcl
# (uses Vivado's xvlog/xelab/xsim, on PATH when run via vivado)

set here [file dirname [file normalize [info script]]]
set src  $here/../src
cd $here

exec xvlog $src/spi_slave_rx.v $src/header_parser.v \
           $here/tb_spi_slave_rx.v $here/tb_header_parser.v

proc run_tb {top} {
    exec xelab $top -s sim_$top
    set out [exec xsim sim_$top -R]
    puts $out
    if {[string first "PASS" $out] < 0} {
        error "$top did not PASS"
    }
}

run_tb tb_spi_slave_rx
run_tb tb_header_parser
