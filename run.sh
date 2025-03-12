#!/bin/bash


#if [ ! "$1" ] || [ ! "$2" ]; then 
#    echo "run.sh <script name> <binary>"
#    exit 1
#fi
#script_name=$1
#binary=$2

if [ ! "$1" ]; then 
    echo "run.sh <binary>"
    exit 1
fi
binary=$1
script_name=GetBasicBlocks

# Make projects directory if it does not exist
__projects_path="${GHIDRA_HOME}/ghidra_projects"
mkdir -p "${__projects_path}"

set -x
 /ghidra/support/analyzeHeadless /ghidra/ghidra_projects ANewProject -readOnly \
     -postScript $script_name \
     -scriptPath "/ghidra_scripts" \
     -import $binary

