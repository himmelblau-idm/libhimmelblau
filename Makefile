all:
	cargo cbuild

install:
	cargo cinstall

clean:
	cargo clean

distclean: clean
	git clean -xfd

dist:
	git archive --format=tar.gz --output ./libhimmelblau-`git describe --tags --abbrev=0`.tar.gz HEAD

check:
	cargo test
