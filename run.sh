#!/bin/bash

cargo build || exit 1
target/debug/rusttcp 10.0.0.1
