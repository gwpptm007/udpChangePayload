#!/bin/bash

# Debian 或 Ubuntu:  sudo apt-get install libnetfilter-queue-dev
# 
# CentOS 或 Fedora:  sudo yum install libnetfilter_queue-devel

make clean
make
if [ $? -eq 0 ]; then
    echo "Compilation successful."
else
    echo "Compilation failed."
    exit 1
fi
