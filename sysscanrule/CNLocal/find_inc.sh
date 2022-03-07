#!/bin/bash
curdir=$(dirname "$0")
plugindir=/opt/GizaNE/lib/GizaNE/plugins

fs=$(grep 'include\s*(' "$curdir"/ -r | awk -F: '{print $2}' | awk -F'['\''"]' '{print $2}' | sort | uniq)
all=""
for f in $fs; do
	f=$(basename "$f")
	echo $f
	f=$plugindir/$f
	cp -f "$f" "$curdir"/
done
