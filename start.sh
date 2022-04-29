#!/bin/bash

/usr/local/sbin/entrypoint.sh
echo "enter"
read line

/opt/dionaea/bin/dionaea -D

python3 sniff.py
