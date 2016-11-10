gcc -DMAIN -I. AE_minizip.c AE_zlib.c AE_openssl.c -lz -llibcrypto -otest1.exe
gcc -DMAIN -I. AE_minizip.c AE_zlib.c AE_botan.c -lz -lbotan -otest2.exe
gcc -DMAIN -I. -I /usr/include AE_minizip.c AE_zlib.c AE_gcrypt.c -L /usr/lib -lz -llibgcrypt -otest3.exe
gcc -DMAIN -I. AE_minizip.c AE_zlib.c AE_nss.c -lz -lnss3 -otest4.exe

gcc -I. -I /usr/include cryptocmd.c AE_minizip.c AE_zlib.c AE_gcrypt.c -L /usr/lib -lz -llibgcrypt -o cryptocmd.exe
