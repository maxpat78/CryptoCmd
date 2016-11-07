/*
   Provides high level functions to create and extract a deflated & AES-256
   encrypted ZIP archive in memory.

   A summary of ZIP archive with strong encryption layout (according to WinZip
   specs: look at http://www.winzip.com/aes_info.htm) follows.

  Local file header:
    local file header signature     4 bytes  (0x04034b50)
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes

    filename (variable size)
    extra field (variable size)

  Extended AES header (both local & central) based on WinZip 9 specs:
    extra field header      2 bytes  (0x9901)
    size                    2 bytes  (7)
    version                 2 bytes  (1 or 2)
    ZIP vendor              2 bytes  (actually, AE)
    strength                1 byte   (AES 1=128-bit key, 2=192, 3=256)
    actual compression      2 byte   (becomes 0x99 in LENT & CENT)

    content data, as follows:
    random salt (8, 12 or 16 byte depending on key size)
    2-byte password verification value (from PBKDF2 with SHA-1, 1000 rounds)
    AES encrypted data (CTR mode, little endian counter)
    10-byte authentication code for encrypted data from HMAC-SHA1

NOTE: AE-1 preserves CRC-32 on uncompressed data, AE-2 sets it to zero.

  Central File header:
    central file header signature   4 bytes  (0x02014b50)
    version made by                 2 bytes
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes
    file comment length             2 bytes
    disk number start               2 bytes
    internal file attributes        2 bytes
    external file attributes        4 bytes
    relative offset of local header 4 bytes

    filename (variable size)
    extra field (variable size)
    file comment (variable size)

  End of central dir record:
    end of central dir signature    4 bytes  (0x06054b50)
    number of this disk             2 bytes
    number of the disk with the
    start of the central directory  2 bytes
    total number of entries in
    the central dir on this disk    2 bytes
    total number of entries in
    the central dir                 2 bytes
    size of the central directory   4 bytes
    offset of start of central
    directory with respect to
    the starting disk number        4 bytes
    zipfile comment length          2 bytes
    zipfile comment (variable size)
*/
#include <mZipAES.h>
#include <time.h>

int MiniZipAE1Write(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password)
{
	char *tmpbuf = NULL;
	unsigned int buflen;
	long crc = 0;
	char salt[16];
	char* aes_key;
	char* hmac_key;
	char* vv;
	char *ppbuf;
	char *digest, *p;
	time_t t;
	struct tm *ptm;

	if (!srcLen || !password)
		return 1;

	crc = AE_crc(0, src, srcLen);

	if (AE_deflate(src, srcLen, &tmpbuf, &buflen))
		return 2;

	if (AE_gen_salt(salt, 16))
		return 3;

	// Encrypts with AES-256 always!
	if (AE_derive_keys(password, salt, 16, &aes_key, &hmac_key, &vv))
		return 4;
	
	if (AE_ctr_crypt(aes_key, 32, tmpbuf, buflen, &ppbuf))
		return 5;

	if (AE_hmac_sha1_80(hmac_key, 32, ppbuf, buflen, &digest))
		return 6;
	
	tmpbuf = (char*) realloc(tmpbuf, buflen+4096);
	p = tmpbuf;

	if (!p)
		return 7;

#define PDW(a, b) *((int*)(p+a)) = b
#define PW(a, b) *((short*)(p+a)) = b

	// Builds the ZIP Local File Header
	PDW(0, 0x04034B50);
	PW(4, 0x33);
	PW(6, 1);
	PW(8, 99);
	time(&t);
	ptm = localtime(&t);
	PW(10, ptm->tm_hour << 11 | ptm->tm_min << 5 | (ptm->tm_sec / 2));
	PW(12, (ptm->tm_year - 80) << 9 | (ptm->tm_mon+1) << 5 | ptm->tm_mday);
	PDW(14, crc);
	PDW(18, buflen+28);
	PDW(22, srcLen);
	PW(26, 4);
	PW(28, 11);
	memcpy(p + 30, "data", 4);
	// Builds the extended AES Header
	PW(34, 0x9901);
	PW(36, 7);
	PW(38, 1);
	PW(40, 0x4541);
	*((char*)(p + 42)) = 3;
	PW(43, 8);

	// Copies the raw contents: salt, check word, encrypted data and HMAC
	memcpy(p + 45, salt, 16);
	memcpy(p + 61, vv, 2);
	memcpy(p + 63, ppbuf, buflen);
	memcpy(p + 63 + buflen, digest, 10);

	p = tmpbuf + 63 + buflen + 10;

	// Builds the ZIP Central File Header
	PDW(0, 0x02014B50);
	PW(4, 0x33);
	PW(6, 0x33);
	PW(8, 1);
	PW(10, 99);
	PW(12, ptm->tm_hour << 11 | ptm->tm_min << 5 | (ptm->tm_sec / 2));
	PW(14, (ptm->tm_year - 80) << 9 | (ptm->tm_mon+1) << 5 | ptm->tm_mday);
	PDW(16, crc);
	PDW(20, buflen + 28);
	PDW(24, srcLen);
	PW(28, 4);
	PW(30, 11);
	PW(32, 0);
	PW(34, 0);
	PW(36, 0);
	PDW(38, 0x20);
	PDW(42, 0);
	memcpy(p + 46, "data", 4);
	// Builds the extended AES Header
	PW(50, 0x9901);
	PW(52, 7);
	PW(54, 1);
	PW(56, 0x4541);
	*((char*)(p + 58)) = 3;
	PW(59, 8);

	p += 61;
	// Builds the End Of Central Dir Record
	PDW(0, 0x06054B50);
	PW(4, 0);
	PW(6, 0);
	PW(8, 1);
	PW(10, 1);
	PDW(12, 61);
	PDW(16, 63 + buflen + 10);
	PW(20, 0);

	*dst = tmpbuf;
	*dstLen = (p+22) - tmpbuf;

	free(ppbuf);
	
	return 0;
}



int MiniZipAE1Read(char* src, unsigned long srcLen, char** dst, unsigned long *dstLen, char* password)
{
	char *tmpbuf = NULL;
	long crc = 0;
	char* salt;
	char* aes_key;
	char* hmac_key;
	char* vv;
	char *digest, *pbuf;

	if (!srcLen || !password)
		return 1;

#define GDW(a) *((unsigned int*)(src+a))
#define GW(a) *((unsigned short*)(src+a))

	// Some sanity checks to ensure it is a compatible ZIP
	if (GDW(0) != 0x04034B50 || GW(8) != 99 ||
		GW(28) != 11 || GW(34) != 0x9901 || GW(38) != 1 || GW(40) != 0x4541 || *((char*)(src + 42)) != 3)
		return 2;
	
	salt = src + 45;

	// Here we regenerate the AES key, the HMAC key and the 16-bit verification value
	if (AE_derive_keys(password, salt, 16, &aes_key, &hmac_key, &vv))
		return 3;
	
	// Compares the 16-bit verification values
	if (GW(61) != *((unsigned short*)vv))
		return 4;

	// Compares the HMACs
	if (AE_hmac_sha1_80(hmac_key, 32, src+63, GDW(18)-28, &digest))
		return 5;
	if (memcmp(digest, src+63+GDW(18)-28, 10))
		return 6;

	// Decrypts into a temporary buffer
	if (AE_ctr_crypt(aes_key, 32, src+63, GDW(18)-28, &pbuf))
		return 7;

	tmpbuf = (char*) malloc(GDW(22));

	if (AE_inflate(pbuf, GDW(18)-28, tmpbuf, GDW(22)))
		return 8;
	
	crc = AE_crc(0, tmpbuf, GDW(22));

	// Compares the CRCs on uncompressed data
	if (crc != GDW(14))
		return 9;

	*dst = tmpbuf;
	*dstLen = GDW(22);

	free(pbuf);

	return 0;
}


#ifdef MAIN
#include <stdio.h>
void main()
{
	char *s = "Questo testo è la sorgente da comprimere e cifrare con MiniZipAE1Write, per poi verificarne l'uguaglianza con il prodotto di MiniZipAE1Read!";
	char *out = NULL;
	int outLen, r;
	//~ FILE *f = fopen("a.zip", "wb");
	r = MiniZipAE1Write(s, strlen(s), &out, &outLen, "kazookazaa");
	printf("MiniZipAE1Write returned %d\n", r);
	r = MiniZipAE1Read(out, outLen, &out, &outLen, "kazookazaa");
	printf("MiniZipAE1Read returned %d\n", r);
	if (outLen != strlen(s) || memcmp(s, out, outLen) != 0)
		puts("SELF TEST FAILED!");
	else
		puts("SELF TEST PASSED!");
	//~ fwrite(out, 1, outLen, f);
	//~ fclose(f);
}
#endif
