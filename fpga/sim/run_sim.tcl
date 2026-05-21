# Compile and run the SPI slave testbench headless; errors if it doesn't PASS.
#   vivado -mode batch -source run_sim.tcl
# (uses Vivado's xvlog/xelab/xsim, on PATH when run via vivado)

set here [file dirname [file normalize [info script]]]
set src  $here/../src
cd $here

exec xvlog $src/spi_slave_rx.v $here/tb_spi_slave_rx.v
exec xelab tb_spi_slave_rx -s tb_run
set out [exec xsim tb_run -R]
puts $out
if {[string first "PASS" $out] < 0} {
    error "simulation did not PASS"
}
