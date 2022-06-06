#!/bin/bash
/opt/dionaea/bin/dionaea -D
zerotier-one -p9993 -d
python3 sniff.py 
