#!/bin/bash

/usr/local/sbin/entrypoint.sh &

/opt/dionaea/bin/dionaea -D

python3 sniff.py
