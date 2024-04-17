#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define MAX_FILENAME_LEN 256
#define BUFFER_SIZE 2048


typedef struct {
    char name[MAX_FILENAME_LEN];
    ino_t inode;
    off_t size;
    time_t mtime;
    nlink_t nlinks;
    mode_t permissions;
} FileMetadata;

int has_snapshot(const char *dirname);
void create_snapshot(const char *dirname);
void create_recursive_snapshot(const char *dirname, int snapshot_fd);
int get_file_metadata(const char *filename, FileMetadata *metadata);
void update_snapshot(const char *dirname);


int get_file_metadata(const char *filename, FileMetadata *metadata) {
    struct stat file_stat;
    if (lstat(filename, &file_stat) == -1) {
        perror("Error getting file metadata");
        return -1;
    }

    strcpy(metadata->name, filename);
    metadata->inode = file_stat.st_ino;
    metadata->size = file_stat.st_size;
    metadata->mtime = file_stat.st_mtime;
    metadata->nlinks = file_stat.st_nlink;
    metadata->permissions = file_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    return 0;
}

int has_snapshot(const char *dirname){

    char snapshot[MAX_FILENAME_LEN];
    strcpy(snapshot, ""); /// init

    /// Pentru primul apel daca nu am mai avut snapshot niciodata
    if( snprintf(snapshot, MAX_FILENAME_LEN,"%s.snapshot", dirname) < 1 ){
        perror("Snapshot verify error");
        exit(EXIT_FAILURE);
    }

    /// Man 2 access folosit cu  F_OK verif daca un fisier exista exista
    return access(snapshot, F_OK) == 0;
}

void create_snapshot(const char *dirname) {

    char snapshot_name[MAX_FILENAME_LEN];
    strcpy(snapshot_name,"");
    snprintf(snapshot_name,MAX_FILENAME_LEN, "%s.snapshot", dirname);

    /// 0 -> octal, 6 -> wr- permissions, 4 -> r-- permissions
    int snapshot_fd = open(snapshot_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (snapshot_fd < 0) {
        perror("Error creating snapshot file");
        exit(EXIT_FAILURE);
    }

    /// Culegem metadatele pentru directorul tarcget apoi le asfisam in snapshot
    FileMetadata dir_metadata;
    if (get_file_metadata(dirname, &dir_metadata) != -1) {
        char metadata_text[BUFFER_SIZE];
        snprintf(metadata_text, BUFFER_SIZE, "Directory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %o\n\n",
                 dir_metadata.name, 
                 (unsigned long)dir_metadata.inode, 
                 (long)dir_metadata.size, 
                 ctime(&dir_metadata.mtime), 
                 (long)dir_metadata.nlinks, 
                 dir_metadata.permissions
                 );
        write(snapshot_fd, metadata_text, strlen(metadata_text));
    }

    /// Parcurgem restul directorului
    create_recursive_snapshot(dirname, snapshot_fd);

    close(snapshot_fd);
    /// YAY AM REUSIT SA CREEM UN SNAPSHOT
    printf("Snapshot created successfully for directory: %s\n", dirname);
}

/// Scriere intreaga a ierarhii de directoare inc. subdir
void create_recursive_snapshot(const char *dirname, int snapshot_fd) {
    // Parcurge directoarele din directorul curent
    DIR *dir = opendir(dirname);
    if (dir == NULL) {
        perror("Error opening directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /// ignorăm .. și . altfel loop infinit
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            // Calea către subdirector
            char subdir_path[MAX_FILENAME_LEN];
            snprintf(subdir_path, MAX_FILENAME_LEN - 1, "%s/%.*s", dirname, (int)strlen(entry->d_name), entry->d_name);

            // Obține informațiile despre elementul curent
            struct stat element;
            if (lstat(subdir_path, &element) < 0) {
                perror("lstat");
                continue;
            }

            FileMetadata metadata;
            get_file_metadata(subdir_path, &metadata);
            char metadata_text[BUFFER_SIZE];
            int offset = 0;

            if (S_ISDIR(element.st_mode)) {
                // Dacă este subdirector, creează snapshot-ul pentru subdirector recursiv
                offset += snprintf(metadata_text + offset, BUFFER_SIZE - offset,"Subdirectory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %o\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                create_recursive_snapshot(subdir_path, snapshot_fd);
            } else if (S_ISREG(element.st_mode)) {
                // Dacă este fișier, obține metadatele și le scrie în snapshot
                    offset += snprintf(metadata_text + offset, BUFFER_SIZE - offset,"File: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %o\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
            }

            // Scrie metadatele în fișierul de snapshot
            write(snapshot_fd, metadata_text, offset);
        }
    }

    closedir(dir);
}

void update_snapshot(const char *dirname) {
    create_snapshot(dirname); // Suprascrie snapshot-ul existent cu cel nou
}

int main(int argc, char *argv[]){

    struct stat sb;

    /// Verificare numar argumente
    if (argc < 3 || argc > 13){

        fprintf(stderr, "Invalid number of arguments!\n Usage: %s <dir_name_0> ... -o <output_dir> ... <dir_name_n>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /// Verificare argumente identice + Daca avem director de output
    int i;
    int j;
    int poz_dir_output = -1;

    for (i = 1; i < argc; i++){

        for (j = i + 1; j < argc; j++){
            if (strcmp(argv[i], argv[j]) == 0 ){

                fprintf(stderr,"Arguments are repeating!\n");
            }
        }

        /// Verificare director de output
        if (strcmp("-o", argv[i]) == 0){

            if (i + 1 >= argc){
                fprintf(stderr,"No output directory\n");
                exit(EXIT_FAILURE);
            }

            /// Verificam daca avem flaguri de output consecutive -o -o -o 
            if (strcmp(argv[i+1],"-o") == 0){
                fprintf(stderr, "No more than one -o flag can exist\n");
                exit(EXIT_FAILURE);
            }

            ///Verificam daca mai incercam sa creem alte directoare de output
            if (poz_dir_output != -1){
                fprintf(stderr,"No more than one output directory can exist\n");
            }

            /// Daca nu exista directorul dupa -o il creem
            if (lstat(argv[i + 1], &sb) < 0){
                perror("Output directory");

                /// Nu avem director deci creem (Output_dir nume default daca nu avem output dir deja existent)
                if (mkdir("Output_dir", 0755) == -1){

                    perror("Couldn't create output directory!");
                    exit(EXIT_FAILURE);
                }
                poz_dir_output = i + 1;
            }

            /// verificam daca argumentul dupa -o este director
            if(!S_ISDIR(sb.st_mode)){

                fprintf(stderr,"%s is not a directory");
                exit(EXIT_FAILURE);
            }
            /// Daca am ajuns aici sigur i + 1 este output directory si exista
            poz_dir_output = i + 1;
        }


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

    /// Daca am ajuns aici stim ca argv[1] este director
    if (!has_snapshot(argv[1])){
        create_snapshot(argv[1]);
    }
    else{
        update_snapshot(argv[1]);
    }

    return 0;
}