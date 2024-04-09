#include <stdio.h>
#include <errno.h>

int main(int argc, char *argv[]){

    if (argc != 2){

        perror("Invalid number of arguments!");
        exit(EXIT_FAILURE);
    }

    return 0;
}