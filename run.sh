#!/bin/bash

cargo build || exit 1
sudo route -n delete -net 10.0.0.0/24 10.0.0.1
#sudo route -n add -net 10.0.0.0/24 10.0.0.1
sudo target/debug/rusttcp 10.0.0.1
