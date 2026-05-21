# Build the NIDS top to a bitstream.
#   vivado -mode batch -source build.tcl

set origin   [file dirname [file normalize [info script]]]
set proj_dir $origin/build/nids

create_project -force nids $proj_dir -part xc7a35tcpg236-1

add_files -norecurse [list $origin/src/nids_top.v $origin/src/spi_slave_rx.v]
add_files -fileset constrs_1 -norecurse $origin/constraints/nids.xdc
set_property top nids_top [current_fileset]
update_compile_order -fileset sources_1

launch_runs synth_1 -jobs 4
wait_on_run synth_1
if {[get_property PROGRESS [get_runs synth_1]] ne "100%"} {
    error "synthesis failed: [get_property STATUS [get_runs synth_1]]"
}

launch_runs impl_1 -to_step write_bitstream -jobs 4
wait_on_run impl_1
if {[get_property PROGRESS [get_runs impl_1]] ne "100%"} {
    error "implementation/bitstream failed: [get_property STATUS [get_runs impl_1]]"
}

set bit $proj_dir/nids.runs/impl_1/nids_top.bit
if {![file exists $bit]} {
    error "no bitstream produced at $bit"
}
puts "BITSTREAM_OK $bit"
