#!/usr/bin/env bash
# Copyright Contributors to the L3AF Project.
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

# declare an array variable
declare -a progs=("xdp-root" "ratelimiting" "connection-limit" "tc-root" "ipfix-flow-exporter" "traffic-mirroring")

# now loop through the above array and build the L3AF eBPF programs
for prog in "${progs[@]}"
do
	cd $prog
	make
	cd ../
done
