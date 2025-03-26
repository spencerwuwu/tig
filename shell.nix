with import <nixpkgs> {};

pkgsCross.riscv32.mkShell {
  packages = with pkgsCross.riscv32.buildPackages; [
    graphviz
	libllvm
    (python3.withPackages (ps: with ps; [
      sympy
      networkx
      matplotlib
      pygraphviz
    ]))
  ];
}

