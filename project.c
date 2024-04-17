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

int has_snapshot(const char *dirname, const char *output_dir);
void create_snapshot(const char *dirname, const char *output_dir);
void create_recursive_snapshot(const char *dirname, int snapshot_fd);
int get_file_metadata(const char *filename, FileMetadata *metadata);
void update_snapshot(const char *dirname, const char *output_dir);


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

int has_snapshot(const char *dirname, const char *output_dir){

    char snapshot[MAX_FILENAME_LEN];
    strcpy(snapshot, ""); /// init

    /// Pentru primul apel daca nu am mai avut snapshot niciodata
    if( snprintf(snapshot, MAX_FILENAME_LEN,"%s/%s.snapshot", output_dir, dirname) < 1 ){
        perror("Snapshot verify error");
        exit(EXIT_FAILURE);
    }

    /// Man 2 access folosit cu  F_OK verif daca un fisier exista exista
    return access(snapshot, F_OK) == 0;
}



int compare_snapshots(const char *snapshot1_path, const char *snapshot2_path) {
    int fd1 = open(snapshot1_path, O_RDONLY);
    int fd2 = open(snapshot2_path, O_RDONLY);

    if (fd1 < 0 || fd2 < 0) {
        perror("Error opening snapshot files");
        exit(EXIT_FAILURE);
    }

    // Compară conținutul fișierelor byte cu byte
    char buffer1[BUFFER_SIZE];
    char buffer2[BUFFER_SIZE];
    ssize_t bytes_read1, bytes_read2;

    do {
        bytes_read1 = read(fd1, buffer1, BUFFER_SIZE);
        bytes_read2 = read(fd2, buffer2, BUFFER_SIZE);

        if (bytes_read1 != bytes_read2 || memcmp(buffer1, buffer2, bytes_read1) != 0) {
            // Dacă se găsește o diferență, închide fișierele și returnează false
            close(fd1);
            close(fd2);
            return 0;
        }
    } while (bytes_read1 > 0 && bytes_read2 > 0);

    // Închide fișierele și returnează true dacă nu s-au găsit diferențe
    close(fd1);
    close(fd2);
    return 1;
}

void create_snapshot(const char *dirname, const char *output_dir) {
    char snapshot_name[MAX_FILENAME_LEN];
    char old_snapshot_name[MAX_FILENAME_LEN];
    snprintf(snapshot_name, MAX_FILENAME_LEN, "%s/%s.snapshot", output_dir, dirname);
    snprintf(old_snapshot_name, MAX_FILENAME_LEN, "%s/%s.old", output_dir, dirname);

    // Check if there is an existing snapshot
    int snapshot_fd = open(snapshot_name, O_RDONLY);
    if (snapshot_fd >= 0) {
        // If there is an existing snapshot, read its content
        char existing_snapshot_text[BUFFER_SIZE];
        ssize_t bytes_read = read(snapshot_fd, existing_snapshot_text, BUFFER_SIZE);
        if (bytes_read < 0) {
            perror("Error reading existing snapshot");
            exit(EXIT_FAILURE);
        }
        close(snapshot_fd);

        // Collect metadata for the target directory
        FileMetadata dir_metadata;
        if (get_file_metadata(dirname, &dir_metadata) != -1) {
            char new_snapshot_text[BUFFER_SIZE];
            snprintf(new_snapshot_text, BUFFER_SIZE, "Directory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %o\n\n",
                     dir_metadata.name, 
                     (unsigned long)dir_metadata.inode, 
                     (long)dir_metadata.size, 
                     ctime(&dir_metadata.mtime), 
                     (long)dir_metadata.nlinks, 
                     dir_metadata.permissions
                     );

            
            // Create a new snapshot
            int new_snapshot_fd = open(snapshot_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (new_snapshot_fd < 0) {
                perror("Error creating snapshot file");
                exit(EXIT_FAILURE);
            }

            create_recursive_snapshot(dirname, new_snapshot_fd);
            write(new_snapshot_fd, new_snapshot_text, strlen(new_snapshot_text));
            close(new_snapshot_fd);

            printf("%s\n***\n%s",existing_snapshot_text,new_snapshot_text);
            printf("MEMCMP - %d\n %ld\n %ld\n",memcmp(existing_snapshot_text, new_snapshot_text, bytes_read), bytes_read, strlen(new_snapshot_text));

            // Check if the new snapshot text differs from the existing one
            if (bytes_read != strlen(new_snapshot_text) || memcmp(existing_snapshot_text, new_snapshot_text, bytes_read) != 0) {

                // If there's a difference, rename the existing snapshot to old
                if (rename(snapshot_name, old_snapshot_name) != 0) {
                    perror("Error renaming old snapshot");
                    exit(EXIT_FAILURE);
                }
                printf("Old snapshot renamed: %s\n", old_snapshot_name);
                printf("Snapshot updated for directory: %s\n", dirname);
            } else {
                printf("No modification detected. Snapshot remains unchanged for directory: %s\n", dirname);
            }

        }
    } 
    else {
        // If there is no existing snapshot, create a new one
        int new_snapshot_fd = open(snapshot_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (new_snapshot_fd < 0) {
            perror("Error creating snapshot file");
            exit(EXIT_FAILURE);
        }

        // Collect metadata for the target directory and write it to the snapshot
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
            write(new_snapshot_fd, metadata_text, strlen(metadata_text));
        }

        // Traverse the rest of the directory
        create_recursive_snapshot(dirname, new_snapshot_fd);

        close(new_snapshot_fd);
        printf("Snapshot created successfully for directory: %s\n", dirname);
    }
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

void update_snapshot(const char *dirname, const char *output_dir) {
    create_snapshot(dirname, output_dir); // Suprascrie snapshot-ul existent cu cel nou
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
                fprintf(stderr, "No more than one -o flags can exist\n");
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
                char output_dir[MAX_FILENAME_LEN];
                strncpy(output_dir,argv[i + 1], MAX_FILENAME_LEN);

                if (mkdir(output_dir, 0755) == -1){

                    perror("Couldn't create output directory!");
                    exit(EXIT_FAILURE);
                }
                poz_dir_output = i + 1;
            }
            
            /// In caz ca nu exista directorul si doar l-am creat
            if (lstat(argv[i + 1], &sb) < 0){
                perror("lstat for output directory test");
                exit(EXIT_FAILURE);
            }

            /// verificam daca argumentul dupa -o este director
            if(!S_ISDIR(sb.st_mode)){

                fprintf(stderr,"%s is not a directory\n", argv[i]);
                exit(EXIT_FAILURE);
            }

            /// Daca am ajuns aici sigur i + 1 este output directory si exista
            poz_dir_output = i + 1;
        }


    }

    /// Snapshot pentru fiecare director in output
    for (i = 1; i < argc; i++){

        /// Nu are sens sa facem snapshot pe directorul de output
        if ( (i == poz_dir_output) || (i == poz_dir_output - 1) ){
            continue;
        }

        /// Lstat citim datele lui argv[i] in stat (detalii in man 2 lstat / lab 4)
        struct stat stat;

        if (lstat(argv[i], &stat) < 0){
            perror("lstat");
            exit(EXIT_FAILURE);
        }

        /// Din stat extragem st_mode si folosim un macro pt a verifica daca este un director (lab 4 jos de tot)
        if (!S_ISDIR(stat.st_mode)){
            fprintf(stderr, "%s is not a directory\n", argv[i]);
            exit(EXIT_FAILURE);
        }

        /// Daca am ajuns aici stim ca argv[i] este director
        if (!has_snapshot(argv[i], argv[poz_dir_output])){
            create_snapshot(argv[i], argv[poz_dir_output]);
        }
        else{
            update_snapshot(argv[i], argv[poz_dir_output]);
        }
    }

    return 0;
}
