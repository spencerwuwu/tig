#!/bin/bash

if [ ! "$1" ] || [ ! "$2" ]; then 
    echo "run.sh <script name> <binary>"
    exit 1
fi

# Make projects directory if it does not exist
__projects_path="${GHIDRA_HOME}/ghidra_projects"
mkdir -p "${__projects_path}"

set -x
 /ghidra/support/analyzeHeadless /ghidra/ghidra_projects ANewProject -readOnly \
     -postScript $1 \
     -scriptPath "/ghidra_scripts" \
     -import $2

