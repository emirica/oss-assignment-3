oss-assignment-3
================
Author: Emma Mirică

Encryption API Benchmark

Test Environment:
    Virtual machine
    Linux Mint Mate 32-bit
        * Linux version 3.2.0-4-486 (debian-kernel@lists.debian.org) (gcc version
    4.6.3 (Debian 4.6.3-12) ) #1 Debian 3.2.32-1
    CPU info:
        * processor : 0
        * vendor_id   : GenuineIntel
        * cpu family  : 6
        * model       : 42
        * model name  : Intel(R) Core(TM) i7-2860QM CPU @ 2.50GHz
        * address sizes   : 40 bits physical, 48 bits virtual
        * cache size  : 8192 KB
    Memory info:
        * MemTotal:        2074900 kB
        * MemFree:          890580 kB
        * Buffers:           60312 kB
        * Cached:           574728 kB
        * SwapCached:            0 kB
        * Active:           739128 kB
        * Inactive:         393696 kB

Documentation:
libgcrypt:
    * http://www.gnupg.org/documentation/manuals/gcrypt.pdf
    * http://www.linuxfromscratch.org/blfs/view/svn/general/libgcrypt.html
    * Install libgcrypt + libgpg-error libraries
        * goto download page
        * get the libgpg-error archive
        * extract libgpg-error archive and run:
        $ ./configure --prefix=/usr --disable-static && make
        # make install && install -v -m644 -D README /usr/share/doc/libgpg-error-1.11/README
        * goto download page
        * get the libgcrypt archive and extract it
        * run:
        ./configure --prefix=/usr --disable-static && make
        [Optional] For documentation:
        make -C doc pdf ps html &&
        makeinfo --html --no-split -o doc/gcrypt_nochunks.html doc/gcrypt.texi
        &&
        makeinfo --plaintext       -o doc/gcrypt.txt           doc/gcrypt.texi
        As root run:
        make install &&
        install -v -dm755   /usr/share/doc/libgcrypt-1.5.2 &&
        install -v -m644    README doc/{README.apichanges,fips*,libgcrypt*} \
                            /usr/share/doc/libgcrypt-1.5.2

botan:
    * http://grip.espace-win.org/doc/apps/botan/api.pdf
    * https://github.com/randombit/botan/tree/net.randombit.botan/doc/examples
    * Install:
        * download library
        * $ ./configure.py
        * $ make; make check
        * # make install
