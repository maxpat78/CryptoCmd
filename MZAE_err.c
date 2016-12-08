/*
 *  Copyright (C) 2016  <maxpat78> <https://github.com/maxpat78>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
	if (code == MZAE_ERR_BUFFER)
		return "Insufficient buffer size";
	if (code == MZAE_ERR_BADZIP)
		return "Bad document format";
	if (code == MZAE_ERR_BADHMAC)
		return "Bad HMAC on encrypted data";
	if (code == MZAE_ERR_BADCRC)
		return "Bad CRC on uncompressed data";
	if (code == MZAE_ERR_BADVV)
		return "Wrong password";
	if (code == MZAE_ERR_NOPW)
		return "Empty password";
	return "Unknown error";
}
