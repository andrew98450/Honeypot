#!/bin/bash

echo '/usr/local/sbin/entrypoint.sh &' >> /entrypoint.sh

echo '/opt/dionaea/bin/dionaea -D' >> /entrypoint.sh

echo 'python3 sniff.py' >> /entrypoint.sh
