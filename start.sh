#!/bin/sh
zerotier-one -d
service mysql start
service apache2 start
python3 sniff.py
