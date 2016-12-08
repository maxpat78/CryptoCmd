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

#include <mZipAES.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    char opt = 0, *buf=0, *dst;
    int pm, found=1, err;
    long size, reqsize;
    FILE *fi, *fo;

    for (pm=1; pm < argc; pm++)
    {
        if (argv[pm][0] != '/') continue;

        if (argv[pm][1] == '?') {
            printf( "Decrypts or encrypts a text file into a compatible ZIP archive.\n\n" \
            "CRYPTOCMD /D | /E password infile outfile\n\n" \
            "  /D         decrypts\n" \
            "  /E         encrypts\n" );
            return 1;
        }

        opt = toupper(argv[pm][1]);

        if (opt == 'E' || opt == 'D') {
            found++;
            continue;
        }
    }

    argv+=found;
    argc-=found;

    if (opt != 'D' && opt != 'E') {
        puts("You must specify /D or /E to decrypt or encrypt!");
        return 1;
    }

    if (argc < 3) {
        puts("You must specify a password, a source and a destination file to decrypt or encrypt!");
        return 1;
    }

    fi = fopen(argv[1], "rb");
    if (! fi) {
        puts("Couldn't open input file!");
        return 1;
    }
    fo = fopen(argv[2], "wb");
    if (! fo) {
        puts("Couldn't open output file!");
        fclose(fi);
        return 1;
    }

    fseek(fi, 0, SEEK_END);
    size = ftell(fi);
    fseek(fi, 0, SEEK_SET);
    buf = (char*) malloc(size);

    if (!size || !buf || (fread(buf, 1, size, fi) != size)) {
        puts("Error while reading the input file!");
        fclose(fi);
        fclose(fo);
        return 1;
    }
    
    fclose(fi);

    if (opt == 'E') {
        reqsize = 0;
        err = MiniZipAE1Write(buf, size, &dst, &reqsize, argv[0]);
        if (err != MZAE_ERR_SUCCESS) {
            printf("Error while computating the buffer size: %s", MZAE_errmsg(err));
            fclose(fo);
            return 1;
        }
        dst = (char*) malloc(reqsize);
        err = MiniZipAE1Write(buf, size, &dst, &reqsize, argv[0]);
        if (err != MZAE_ERR_SUCCESS) {
            printf("Error while generating the encrypted file: %s", MZAE_errmsg(err));
            fclose(fo);
            return 1;
        }
        printf("Encrypting... ");
    }

    if (opt == 'D') {
        reqsize = 0;
        err = MiniZipAE1Read(buf, size, &dst, &reqsize, argv[0]);
        if (err != MZAE_ERR_SUCCESS) {
            printf("Error while computating the buffer size: %s", MZAE_errmsg(err));
            fclose(fo);
            return 1;
        }
        dst = (char*) malloc(reqsize);
        err = MiniZipAE1Read(buf, size, &dst, &reqsize, argv[0]);
        if (err != MZAE_ERR_SUCCESS) {
            printf("Error while extracting the encrypted file: %s", MZAE_errmsg(err));
            fclose(fo);
            return 1;
        }
        printf("Decrypting... ");
    }

    if (fwrite(dst, 1, reqsize, fo) != reqsize) {
        puts("Error while writing to the output file!");
        fclose(fo);
        return 1;
    }

    fclose(fo);

    printf("done, %d bytes written.", reqsize);
    return 0;
}
