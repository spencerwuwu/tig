with import <nixpkgs> {};
pkgsCross.riscv32-embedded.mkShell {
	packages = with pkgs; [
		python3Packages.numpy
		zlib
	];
	shellHook = ''
		export LD_LIBRARY_PATH="${stdenv.cc.cc.lib}/lib:${zlib.out}/lib";
	'';
}
