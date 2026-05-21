# Build the smoke-test project to a bitstream.
#   vivado -mode batch -source build_smoke.tcl

set origin   [file dirname [file normalize [info script]]]
set proj_dir $origin/build/smoke

create_project -force smoke $proj_dir -part xc7a35tcpg236-1

add_files -norecurse $origin/src/top.v
add_files -fileset constrs_1 -norecurse $origin/constraints/Basys-3-Master.xdc
set_property top top [current_fileset]
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

set bit $proj_dir/smoke.runs/impl_1/top.bit
if {![file exists $bit]} {
    error "no bitstream produced at $bit"
}
puts "BITSTREAM_OK $bit"
