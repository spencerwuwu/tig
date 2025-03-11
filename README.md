# Ghidra Headless Analyzer

Ghidra is a software reverse engineering (SRE) framework created by National Security Agency.
This is an attempt to make docker image for purely decompiling binaries with headless version of Ghidra, and to produce decompiled C - code.

These includes sets of postscripts, which can be run in headless mode.


## Input

```
Any software binary in native instructions.
```

## Output

```
With default script, Decompiled source code in pseudo C - code. Output depends on used scripts.
```

## Usage

### Installation

```
git clone <xxx>
make build  
```

### Running

Analyse a sample in directory "<samples>/<binary>":  

```
docker run --rm -v <samples>/:/samples ghidra-$(whoami) decompile /samples/<binary>
```

Or get possible arguments for the program:  

```
docker run --rm -v <samples>/:/samples ghidra-$(whoami) --help
```

## Project homepage

https://ghidra-sre.org/

See more about Headless Analyzer in [here.](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html)

## Licence

Ghidra itself is distributed under Apache 2.0 licence, however all additional features included here are under MIT licence.
