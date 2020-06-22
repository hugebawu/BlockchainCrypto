#!/usr/bin/env bash
index=1
for arg in $*; do
	echo "arg$index=$arg"
	let index+=1
done

for arg in "$*"; do
	echo $arg
done