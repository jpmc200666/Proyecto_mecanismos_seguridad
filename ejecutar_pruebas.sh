#!/bin/bash
for i in 1 2  3 4 5; do
	echo " Iniciando repeticion $i "
	sudo mn -c
	sudo python3 run_demo.py --attack all
	mkdir -p results/rep$i
	mv results/demo_* results/ping_* results/detector_* results/rep$i/ 2>/dev/null
	echo " Repeticion $i comlpletada "
	sleep 2
done
