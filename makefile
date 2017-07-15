all:
	g++ -std=c++0x admin_app.cpp /usr/local/lib/libcpp_redis.a /usr/local/lib/libtacopie.a pbc_ibbe/ibbe.so -lpthread -I/usr/local/include/pbc -o test.out
