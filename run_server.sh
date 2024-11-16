#!/bin/bash

cargo build --example server || exit 1
target/debug/examples/server 10.0.0.1 10.0.0.2
