#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_options()
{
    printf("Usage: ./nyufile disk <options>\n");
    printf("-i                     Print the file system information.\n");
    printf("-l                     List the root directory.\n");
    printf("-r filename [-s sha1]  Recover a contiguous file.\n");
    printf("-R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

int main(int argc, char *argv[])
{
    int opt, count;
    
    while ((opt = getopt(argc, argv, "ilrR:")) != -1) {
        switch (opt) {
        case 'i':

            break;
        case 'l':

            break;
        case 'r':

            break;
        case 'R':

            break;
        }
    }

    print_options();

    exit(EXIT_SUCCESS);
}