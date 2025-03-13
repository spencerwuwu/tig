#!/bin/bash

killncleanup() {
    docker stop $container_id &> /dev/null
    docker rm -f $container_id &> /dev/null
    exit 0
}

cleanup() {
    docker rm -f $container_id &> /dev/null
    exit 0
}

trap cleanup EXIT 
trap killncleanup SIGINT SIGTERM SIGKILL

if [ ! "$1" ] || [ ! "$2" ] ; then 
    echo "Usage: ./get_ghidra_basicblocks.sh <binary> <out_json>"
    exit 1
fi

binary=$1
out_json=$2

binary_path=$(realpath $(dirname $binary))
binary_name=$(basename $binary)

container_id=$(docker run -dt --rm \
    -v ${binary_path}:/samples ghidra-bbextract \
    /samples/${binary_name}
)
container_id=$(cut -c-12 <<< $container_id)
echo "== Processing $binary with container ${container_id}"

ret=$(docker logs -f "$container_id" &)
exit_code=$(docker wait $container_id)

if [[ "$exit_code" != "0" ]]; then
    echo $ret
    exit 1
else
    echo $ret > $out_json
    echo " - Saving result to $out_json"
fi
