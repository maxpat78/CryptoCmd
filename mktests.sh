gcc -DMAIN -I. MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_openssl.c -lz -lcrypto -otest1.exe
gcc -DMAIN -I. MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_botan.c -lz -lbotan -otest2.exe
gcc -DMAIN -I. -I /usr/include MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_gcrypt.c -L /usr/lib -lz -lgcrypt -otest3.exe
gcc -DMAIN -I. MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_nss.c -lz -lnss3 -otest4.exe

gcc -I. -I /usr/include cryptocmd.c MZAE_err.c MZAE_zlib.c MZAE_openssl.c -lz -lcrypto -L /usr/lib -lz -o cryptocmd.exe
