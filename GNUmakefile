# Name: Emma Mirică
# Project: OSS
# Assignment 3 - Encryption API Benchmark

gcrypt_checker: gcrypt_checker.c
	gcc -o $@ -Wall -g gcrypt_checker.c -lgcrypt

botan_checker: botan_checker.cpp
	g++ -o $@ -Wall -g -I/usr/include/botan-1.10 -L/usr/lib/botan-1.10 botan_checker.cpp -lbotan-1.10

# g++ -o $@ -Wall -g -I/usr/include/crypto++ -L/usr/lib/crypto++ crypto_checker.cpp -lcryptopp
crypto_checker: crypto_checker.cpp
	g++ -o $@ -Wall -g crypto_checker.cpp -lcryptopp

.PHONY: clean
clean:
	rm -f *~ *.o gcrypt_checker botan_checker crypto_checker
