/*
Translate an error code to a human readable message.
*/
#include <mZipAES.h>



char* MZAE_errmsg(int code)
{
	if (code == MZAE_ERR_SUCCESS)
		return "No error";
	if (code == MZAE_ERR_PARAMS)
		return "Bad arguments";
	if (code == MZAE_ERR_CODEC)
		return "Error while (de)compressing data";
	if (code == MZAE_ERR_SALT)
		return "Can't generate a random salt";
	if (code == MZAE_ERR_KDF)
		return "Problem while generating the AES and HMAC keys";
	if (code == MZAE_ERR_AES)
		return "Error while en-/de-crypting data";
	if (code == MZAE_ERR_HMAC)
		return "Can't computate the HMAC";
	if (code == MZAE_ERR_NOMEM)
		return "Can't allocate required memory";
	if (code == MZAE_ERR_BADZIP)
		return "Bad document format";
	if (code == MZAE_ERR_BADHMAC)
		return "Bad HMAC on encrypted data";
	if (code == MZAE_ERR_BADCRC)
		return "Bad CRC on uncompressed data";
	if (code == MZAE_ERR_BADVV)
		return "Wrong password";
	return "Unknown error";
}
