#!/bin/bash

/opt/dionaea/bin/dionaea -D

while; do; nc -lvnp 5555 -c ./pwn_me ; done &

python3 sniff.py 
