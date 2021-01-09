CryptoCmd
=========

A little C utility licensed under GNU GPL (and tested in a 32-bit environment only) to read and write documents created with my CryptoPad/JCryptoPad tools.

Such documents are simple ZIP archives encrypted with AES for maximum security and portability.

It operates always with AES-256.

File contents are deflated before encryption, too.


The well known AE-1 specification from WinZip[1] is implemented, so one of the following cryptographic toolkits/libraries is required to build the app:

- libeay32/libcrypto from OpenSSL[2] or LibreSSL[3]
- Botan[4]
- NSS3 from Mozilla[5]
- Libgcrypt from GNU project[6]

cryptocmd.c is the main command line module.

MZAE_minizip.c provides 2 high level API to write or read a document in memory, in a single pass.

MZAE_zlib.c provides support to Deflate algorithm via Zlib[7].

MZAE_openssl.c implements required cryptographic functions on top of OpenSSL/LibreSSL.

MZAE_botan.c implements required cryptographic functions on top of Botan 2.

MZAE_gcrypt.c implements required cryptographic functions on top of GNU libgcrypt.

MZAE_nss.c implements required cryptographic functions on top of Mozilla NSS3.



[1] See http://www.winzip.com/aes_info.htm

[2] See https://www.openssl.org/

[3] See https://www.libressl.org/

[4] See http://botan.randombit.net/

[5] See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS

[6] See https://www.gnu.org/software/libgcrypt/

[7] See http://zlib.net/
