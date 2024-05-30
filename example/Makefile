all:
	cargo build
	gcc -g msal_example.c -I../target/debug/include -L../target/debug -lmsal

run:
	LD_LIBRARY_PATH=../target/debug ./a.out
