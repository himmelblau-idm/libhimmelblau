all:
	cargo cbuild
	maturin build

install:
	>&2 echo "This is a development install. Do not use this command for packaging."
	sudo cargo cinstall --prefix=/usr/local
	maturin develop

clean:
	cargo clean

distclean: clean
	git clean -xfd

dist:
	git archive --format=tar.gz --output ./libhimmelblau-`git describe --tags --abbrev=0`.tar.gz HEAD

check:
	cargo test
