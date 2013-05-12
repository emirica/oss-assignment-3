# Name: Emma Mirică
# Project: OSS
# Assignment 3 - Encryption API Benchmark

libgcrypt_checker: libgcrypt_checker.c

botan_checker: botan_checker.cpp
	g++ -o $@ -Wall -g -I/usr/include/botan-1.10 -L/usr/lib/botan-1.10 botan_checker.cpp -lbotan-1.10

.PHONY: clean
clean:
	rm -f *~ *.o libgcrypt_checker botan_checker crypto_checker
