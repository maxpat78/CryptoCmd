/*
Provides functions to calculate ZIP crc32 and to deflate and inflate an archive
in a single pass.

Requires Zlib.
*/
#include <mZipAES.h>
#include <stdlib.h>
#include <zlib.h>



unsigned long MZAE_crc(unsigned long crc, char* src, unsigned int srclen)
{
	return crc32(crc, src, srclen);
}



int MZAE_deflate(char* src, unsigned int srclen, char** dst, unsigned int* dstlen)
{
	z_stream zstream;
	*dst = (char*) malloc(srclen+64);

	if (! *dst)
		return 1;

	memset(&zstream, 0, sizeof(zstream));
	zstream.zalloc = Z_NULL;
	zstream.zfree = Z_NULL;
	zstream.opaque = Z_NULL;

	if (deflateInit2(&zstream, 8, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
		return 2;

	zstream.next_in = src;
	zstream.avail_in = srclen;
	zstream.next_out = *dst;
	zstream.avail_out = srclen+64;

	if (deflate(&zstream, Z_FINISH) == Z_STREAM_ERROR)
		return 3;

	deflateEnd(&zstream);
	
	*dstlen = zstream.total_out;

	return 0;
}



int MZAE_inflate(char* src, unsigned int srclen, char* dst, unsigned int dstlen)
{
	z_stream zstream;

	memset(&zstream, 0, sizeof(zstream));
	zstream.zalloc = Z_NULL;
	zstream.zfree = Z_NULL;
	zstream.opaque = Z_NULL;

	if (inflateInit2(&zstream, -15) != Z_OK)
		return 1;

	zstream.next_in = src;
	zstream.avail_in = srclen;
	zstream.next_out = dst;
	zstream.avail_out = dstlen;

	if (inflate(&zstream, Z_NO_FLUSH) != Z_STREAM_END)
		return 2;

	if (zstream.total_out != dstlen)
		return 3;

	inflateEnd(&zstream);
	
	return 0;
}
