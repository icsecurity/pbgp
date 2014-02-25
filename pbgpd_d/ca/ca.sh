#!/bin/sh

if [ ! -f main ]; then
  gcc -O3 -g -ggdb  -Wall -L/usr/local/lib main.c -I/usr/local/include/pbgp -I/usr/local/include -I/usr/local/include/db4 -lpbgp -o main
fi

rm /etc/pbgp/*~ /etc/pbgp/store_epoch /etc/pbgp/store_glb_*

./main | tee main.out
