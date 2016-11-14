#include <mZipAES.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    char opt = 0, *buf=0, *dst;
    int pm, found=1, err;
    long size;
    FILE *fi, *fo;

    for (pm=1; pm < argc; pm++)
    {
        if (argv[pm][0] != '/') continue;

        if (argv[pm][1] == '?') {
            printf( "Encrypts or decrypts a text file.\n\n" \
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

    if (opt == 'E' && (err = MiniZipAE1Write(buf, size, &dst, &size, argv[0]))) {
        printf("Error while generating the encrypted file: %s", MZAE_errmsg(err));
        fclose(fo);
        return 1;
    }

    if (opt == 'D' && (err = MiniZipAE1Read(buf, size, &dst, &size, argv[0]))) {
        printf("Error while extracting the encrypted file: %s", MZAE_errmsg(err));
        fclose(fo);
        return 1;
    }

    if (fwrite(dst, 1, size, fo) != size) {
        puts("Error while writing to the output file!");
        fclose(fo);
        return 1;
    }

    fclose(fo);

    printf("Done, %d bytes written.", size);
    return 0;
}
