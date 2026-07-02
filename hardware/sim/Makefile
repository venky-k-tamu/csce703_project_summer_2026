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

# RTL in dependency order (package first) for the Icarus smoke flow.
SMOKE_RTL = ../../rtl/keccak/keccak_pkg.sv ../../rtl/keccak/keccak_round.sv \
            ../../rtl/keccak/keccak_f1600.sv ../../rtl/keccak/keccak_sponge.sv \
            ../../rtl/keccak/shake_xof.sv

.PHONY: sim smoke vectors clean

vectors:
	cd ../tb/vectors && python3 gen_vectors.py

# Open-source self-checking smoke test (Icarus). No UVM/commercial sim needed.
# Verifies keccak_round + keccak_f1600 + keccak_sponge against hashlib vectors.
smoke:
	cd ../tb/smoke && python3 gen_smoke.py && \
	  iverilog -g2012 -grelative-include -o smoke.vvp -I. $(SMOKE_RTL) tb_smoke.sv && \
	  vvp smoke.vvp

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
	       xcelium.d xrun.* *.log *.vcd ../tb/vectors/*.vec \
	       ../tb/smoke/smoke.vvp ../tb/smoke/smoke_cases.svh ../tb/smoke/fixtures
