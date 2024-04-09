#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

int main(int argc, char *argv[]){

    struct stat sb;

    /// Verificare numar argumente
    if (argc != 2){

        fprintf(stderr, "Invalid number of arguments! Usage: %s <dir_name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /// Lstat citim datele lui argv[0] in sb (detalii in man 2 lstat / lab 4)
    if (lstat(argv[1], &sb) < 0){
        perror("lstat");
        exit(EXIT_FAILURE);
    }

    /// Din sb extragem st_mode si folosim macro pt a verifica daca este un diretor (lab 4 jos de tot)
    if (!S_ISDIR(sb.st_mode)){
        fprintf(stderr, "%s is not a directory\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    return 0;
}