@echo off 
cl -DMAIN -O2 -I. -I \usr\include MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_openssl.c zdll.lib libcrypto.lib /link /libpath:\usr\lib /out:test1.exe 
cl -DMAIN -O2 -I. -I \usr\include MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_botan.c zdll.lib botan.lib /link /libpath:\usr\lib /out:test2.exe 
cl -DMAIN -O2 -I. -I \usr\include MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_gcrypt.c zdll.lib libgcrypt.lib /link /libpath:\usr\lib /out:test3.exe 
cl -DMAIN -O2 -I. -I \usr\include MZAE_minizip.c MZAE_err.c MZAE_zlib.c MZAE_nss.c zdll.lib nss3.lib /link /libpath:\usr\lib /out:test4.exe 

cl -MD -O2 -I. -I \usr\include cryptocmd.c MZAE_minizip.c MZAE_zlib.c MZAE_gcrypt.c zdll.lib libgcrypt.lib /link /libpath:\usr\lib
