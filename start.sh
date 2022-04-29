#!/bin/bash

/opt/dionaea/bin/dionaea -c ./config.cfg -D

python3 sniff.py
