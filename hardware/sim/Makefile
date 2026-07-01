# hardware/sim/Makefile — compile + run the Keccak UVM testbench.
#
# UVM requires a commercial simulator. Select with SIM=questa|vcs|xcelium.
# Choose the UVM test with TEST=<uvm_test_name> (default: keccak_rand_test).
#
#   make vectors                 # regenerate golden vectors (needs python3)
#   make sim SIM=questa
#   make sim SIM=vcs TEST=keccak_kat_test
#   make clean

SIM   ?= questa
TEST  ?= keccak_rand_test
RTL_F  = filelists/rtl.f
TB_F   = filelists/tb.f

.PHONY: sim vectors clean

vectors:
	cd ../tb/vectors && python3 gen_vectors.py

# ---- Questa / ModelSim -----------------------------------------------------
ifeq ($(SIM),questa)
sim: vectors
	vlib work
	vlog -sv +acc -f $(RTL_F) -f $(TB_F) +incdir+$(UVM_HOME)/src \
	     $(UVM_HOME)/src/uvm_pkg.sv
	vsim -c -do "run -all; quit" tb_keccak +UVM_TESTNAME=$(TEST)
endif

# ---- Synopsys VCS ----------------------------------------------------------
ifeq ($(SIM),vcs)
sim: vectors
	vcs -sverilog -ntb_opts uvm -full64 -f $(RTL_F) -f $(TB_F) -o simv
	./simv +UVM_TESTNAME=$(TEST)
endif

# ---- Cadence Xcelium -------------------------------------------------------
ifeq ($(SIM),xcelium)
sim: vectors
	xrun -sv -uvm -f $(RTL_F) -f $(TB_F) +UVM_TESTNAME=$(TEST)
endif

clean:
	rm -rf work transcript vsim.wlf simv simv.daidir csrc \
	       xcelium.d xrun.* *.log *.vcd ../tb/vectors/*.vec
