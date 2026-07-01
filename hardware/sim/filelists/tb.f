// Testbench compile order. Paths relative to hardware/sim/.
// Interface + UVM package (which +includes the class .svh files) + top.
// The +incdir lets the package `include the class files.
+incdir+../tb/keccak
../tb/keccak/keccak_if.sv
../tb/keccak/keccak_uvm_pkg.sv
../tb/top/tb_keccak.sv
