#/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:lib

./bin/server &
./bin/client &

wait

echo "All done."
echo ""
