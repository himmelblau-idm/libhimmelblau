all:
	command -v cargo-cbuild || (echo "cargo-c required" && exit 1)
	cargo cbuild
	command -v maturin || (echo "python3-maturin required" && exit 1)
	maturin build

HOST=`rustc -vV | grep "host" | cut -d ' ' -f2`
DIR=`pwd`
LIB_DIR=${DIR}/target/${HOST}/debug
INCLUDE_DIR=${LIB_DIR}/include

testenv: all
	ln -s ${LIB_DIR}/libhimmelblau.so ${LIB_DIR}/libhimmelblau.so.0 2>/dev/null || echo
	python3 -m venv ./target/.env
	xterm -e "source ./target/.env/bin/activate && maturin develop && LD_LIBRARY_PATH=${LIB_DIR} LDFLAGS="-L${LIB_DIR}" CFLAGS="-I${INCLUDE_DIR}" sh"

clean:
	cargo clean

distclean: clean
	git clean -xfd

dist:
	git archive --format=tar.gz --output ./libhimmelblau-`git describe --tags --abbrev=0`.tar.gz HEAD

check:
	cargo test
