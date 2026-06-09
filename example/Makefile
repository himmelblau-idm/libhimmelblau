all: msal_example msal_obo_example

msal_example:
	gcc -g msal_example.c -lhimmelblau ${LDFLAGS} ${CFLAGS} -o msal_example

msal_obo_example:
	gcc -g msal_obo_example.c -lhimmelblau ${LDFLAGS} ${CFLAGS} -DON_BEHALF_OF -o msal_obo_example

clean:
	rm -f msal_example msal_obo_example
