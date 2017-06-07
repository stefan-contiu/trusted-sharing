all:
	gcc -shared -fPIC bbs.c hash.c -lgmp -lpbc -lssl -lcrypto -lm -L/usr/local/lib/ -I/usr/local/include/pbc -o bbs.so
exe:
	gcc bbs.c hash.c -lgmp -lpbc -lssl -lcrypto -lm -L/usr/local/lib/ -I/usr/local/include/pbc -o bbs.o