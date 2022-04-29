#!/bin/sh

/usr/local/sbin/entrypoint.sh &

python3 sniff.py
