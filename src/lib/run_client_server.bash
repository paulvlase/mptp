#!/bin/bash

LD_LIBRARY_PATH=. ./server &
LD_LIBRARY_PATH=. ./client &

wait

echo -e "All done.\n"
