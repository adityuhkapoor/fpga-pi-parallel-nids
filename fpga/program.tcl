# Program the Basys 3 over JTAG with the smoke-test bitstream.
#   vivado -mode batch -source program.tcl
# Requires the board connected by USB and cable drivers installed.

set origin [file dirname [file normalize [info script]]]
set bit    $origin/build/smoke/smoke.runs/impl_1/top.bit
if {![file exists $bit]} {
    error "bitstream not found at $bit -- run build_smoke.tcl first"
}

open_hw_manager
connect_hw_server

set tgts [get_hw_targets]
if {[llength $tgts] == 0} {
    error "no JTAG target found -- board powered? cable drivers installed?"
}
current_hw_target [lindex $tgts 0]
open_hw_target

set dev [lindex [get_hw_devices] 0]
puts "DEVICE_DETECTED $dev"
current_hw_device $dev
refresh_hw_device -update_hw_probes false $dev

set_property PROGRAM.FILE $bit $dev
program_hw_devices $dev
refresh_hw_device $dev
puts "PROGRAM_OK $dev"

close_hw_target
disconnect_hw_server
