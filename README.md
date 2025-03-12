# Ghidra Headless Analyzer

## Usage

### Installation

```
git clone <xxx>
make build  
docker run --rm -v <samples>/:/samples ghidra-$(whoami) <binary>
```

### Running (legacy decompile)

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
