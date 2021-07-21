#!/bin/bash
mypath=$(dirname $(readlink -f $0))
pushd $mypath/..
make purge && 
make cee_utils &&
make specs_clean &&
make clean_actor_gen &&
make all_headers &&
make specs &&
popd
