gcc -DMAIN -I. MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_openssl.c -lz -lcrypto -otest1.exe
# Insecure AES/ECB is no longer supported in botan-2 library, and native CTR(AES-256,16) stream cipher is Big Endian only!
#gcc -DMAIN -I. -I/mingw32/include/botan-2 MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_botan.c -lz -lbotan-2 -otest2.exe
gcc -DMAIN -I. MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_gcrypt.c -lz -lgcrypt -otest3.exe
gcc -DMAIN -I. -I/mingw32/include/nspr MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_nss.c -lz -lnss3 -otest4.exe
gcc -I. cryptocmd.c MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_openssl.c -lz -lcrypto -lz -o cryptocmd.exe
