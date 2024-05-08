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
#include <sys/wait.h>
#include <errno.h>
#include <libgen.h>


#define MAX_FILENAME_LEN 256
#define BUFFER_SIZE 2048


/// Structura pentru metadatele necesare unui snapshot
typedef struct {
    char name[MAX_FILENAME_LEN];
    ino_t inode;
    off_t size;
    time_t mtime;
    nlink_t nlinks;
    char permissions[10];
} FileMetadata;

void create_snapshot(const char *dirname, const char *output_dir);
void create_recursive_snapshot(const char *dirname, int snapshot_fd);
int get_file_metadata(const char *filename, FileMetadata *metadata);


int get_file_metadata(const char *filename, FileMetadata *metadata) {

    struct stat file_stat;
    mode_t octal_permissions;
    char perms[] = "rwxrwxrwx";

    if (lstat(filename, &file_stat) == -1) {
        perror("Error getting file metadata");
        return -1;
    }

    octal_permissions = file_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    for (int i = 0; i < 9; i++) {
        if (!(octal_permissions & (1 << (8 - i))))
            perms[i] = '-';
    }


    strcpy(metadata->name, filename);
    metadata->inode = file_stat.st_ino;
    metadata->size = file_stat.st_size;
    metadata->mtime = file_stat.st_mtime;
    metadata->nlinks = file_stat.st_nlink;
    strcpy(metadata->permissions,perms);

    return 0;
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
    char temporary_snapshot[MAX_FILENAME_LEN];
    char old_snapshot_name[MAX_FILENAME_LEN];

    snprintf(snapshot_name, MAX_FILENAME_LEN, "%s/%s.snapshot", output_dir, dirname);
    snprintf(temporary_snapshot, MAX_FILENAME_LEN, "%s/%s.snapshot_temp", output_dir, dirname);
    snprintf(old_snapshot_name, MAX_FILENAME_LEN, "%s/%s.snapshot_old", output_dir, dirname);

    // Verificam daca avem deja un snapshot existent
    int snapshot_fd = open(snapshot_name, O_RDONLY);

    if (snapshot_fd >= 0) {

        // Daca avem unul citim datele din el
        char existing_snapshot_text[BUFFER_SIZE];
        strcpy(existing_snapshot_text,"");
        ssize_t bytes_read = read(snapshot_fd, existing_snapshot_text, BUFFER_SIZE);

        if (bytes_read < 0) {
            perror("Error reading existing snapshot");
            exit(EXIT_FAILURE);
        }
        close(snapshot_fd);

        // Creem un nou snapshot temporar pentru directorul target
        FileMetadata dir_metadata;

        if (get_file_metadata(dirname, &dir_metadata) != -1) {
            char new_snapshot_text[BUFFER_SIZE];
            snprintf(new_snapshot_text, BUFFER_SIZE, "Directory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                     dir_metadata.name, 
                     (unsigned long)dir_metadata.inode, 
                     (long)dir_metadata.size, 
                     ctime(&dir_metadata.mtime), 
                     (long)dir_metadata.nlinks, 
                     dir_metadata.permissions
                     );

            
            // Creem fisierul de snapshot pentru comparare
            int temporary_snapshot_fd = open(temporary_snapshot, O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (temporary_snapshot_fd < 0) {
                perror("Error creating compare snapshot file");
                exit(EXIT_FAILURE);
            }

            // Il construim cu toata ierarhia de fisiere/directoare, iar pe urma le comparam
            write(temporary_snapshot_fd, new_snapshot_text, strlen(new_snapshot_text));
            create_recursive_snapshot(dirname, temporary_snapshot_fd);
            close(temporary_snapshot_fd);
            

            /// Nu sunt identice
            if (compare_snapshots(snapshot_name, temporary_snapshot) != 1){
                
                // Am gasit o diferenta deci temp devine actual si acual devine old
                if (rename(snapshot_name, old_snapshot_name) != 0) {
                    perror("Error renaming old snapshot");
                    exit(EXIT_FAILURE);
                }

                if (rename(temporary_snapshot, snapshot_name) != 0) {
                    perror("Error renaming new snapshot");
                    exit(EXIT_FAILURE);
                }

                printf("Old snapshot renamed: %s\n", old_snapshot_name);
                printf("Snapshot updated for directory: %s\n", dirname);
            }
            else{

                printf("No modification detected. Snapshot remains unchanged for directory: %s\n", dirname);

                ///Stergem snapshotul temporar
                if (unlink(temporary_snapshot) == -1){
                    perror("Error unlinking temporary snapshot");
                    exit(EXIT_FAILURE);
                }

            }

        }
    } 
    else {
        // NU Exista dir.snapshot - > deci il creem

        snapshot_fd = open(snapshot_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (snapshot_fd < 0) {
            perror("Error creating snapshot file");
            exit(EXIT_FAILURE);
        }

        // Luam metadeatele pentru directorul argument si le scriem in snapshot
        FileMetadata dir_metadata;
        char metadata_text[BUFFER_SIZE];

        if (get_file_metadata(dirname, &dir_metadata) != -1) {
            snprintf(metadata_text, BUFFER_SIZE, "Directory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                     dir_metadata.name, 
                     (unsigned long)dir_metadata.inode, 
                     (long)dir_metadata.size, 
                     ctime(&dir_metadata.mtime), 
                     (long)dir_metadata.nlinks, 
                     dir_metadata.permissions
                     );
            write(snapshot_fd, metadata_text, strlen(metadata_text));
        }

        // Parcurgem ierarhia subarborelui director
        create_recursive_snapshot(dirname, snapshot_fd);
        close(snapshot_fd);

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
            // Calea către element
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
                offset += snprintf(metadata_text + offset, BUFFER_SIZE - offset,"Subdirectory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, offset); // Adăugăm metadatele subdirectorului la snapshot

                // Creăm snapshot-ul pentru subdirector recursiv
                create_recursive_snapshot(subdir_path, snapshot_fd);

            } 
            else if (S_ISREG(element.st_mode)) {
                // +Verificare daca este fisier suspect
                // nepot - fiu - pipe
                // fiu - parinte - cod retur
                // ....
                // Dacă este fișier, obține metadatele și le scrie în snapshot
                offset += snprintf(metadata_text + offset, BUFFER_SIZE - offset,"File: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, offset); // Adăugăm metadatele fișierului la snapshot
            }
            else if(S_ISLNK(element.st_mode)){

                /// same test as reg file
                offset += snprintf(metadata_text + offset, BUFFER_SIZE - offset,"Link: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, offset); // Adăugăm metadatele fișierului la snapshot
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]){

    /// Verificare numar argumente
    if (argc < 3 || argc > 13){

        fprintf(stderr, "Invalid number of arguments!\n Usage: %s <dir_name_0> ... -o <output_dir> ... <dir_name_n>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /// Verificare argumente identice + Daca avem director de output
    int i;
    int j;
    int poz_dir_output = -1;
    int poz_dir_carantina = -1;
    struct stat sb;

    for (i = 1; i < argc; i++){

        for (j = i + 1; j < argc; j++){
            if (strcmp(argv[i], argv[j]) == 0 ){

                fprintf(stderr,"Arguments are repeating!\n");
            }
        }

        //########## SE POATE MODULARIZA ############
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
                exit(EXIT_FAILURE);
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

            /// verificam daca argumentul dupa -o este director
           if (lstat(argv[i + 1], &sb) < 0){
                perror("Output director test eror");
                exit(EXIT_FAILURE);
           }
           else{
                if(!S_ISDIR(sb.st_mode)){
                    fprintf(stderr,"%s is not a directory\n", argv[i + 1]);
                    exit(EXIT_FAILURE);
                }
           }

            /// Daca am ajuns aici sigur i + 1 este output directory si exista
            poz_dir_output = i + 1;
        }

        /// ########## SE POATE MODULARIZA ############
        /// Verificare director de carantina
        if (strcmp("-x", argv[i]) == 0){

            if (i + 1 >= argc){
                fprintf(stderr,"No quarantine directory can be found along the arguments\n");
                exit(EXIT_FAILURE);
            }

             /// Verificam daca avem flaguri de output consecutive -x -x -x 
            if (strcmp(argv[i+1],"-x") == 0){
                fprintf(stderr, "No more than one -x flags can exist\n");
                exit(EXIT_FAILURE);
            }

            ///Verificam daca mai incercam sa creem alte directoare de carantina
            if (poz_dir_carantina != -1){
                fprintf(stderr,"No more than one quarantine directory can exist\n");
                exit(EXIT_FAILURE);
            }

            /// Daca nu exista directorul dupa -x il creem
            if (lstat(argv[i + 1], &sb) < 0){
                printf("Trying to create quarantine directory...\n");
                /// Nu avem director deci creem (quaratine_dir nume default daca nu avem quarantine dir deja existent)
                char quaratine_dir[MAX_FILENAME_LEN];
                strncpy(quaratine_dir,argv[i + 1], MAX_FILENAME_LEN);

                if (mkdir(quaratine_dir, 0755) == -1){

                    perror("Couldn't create quarantine directory!");
                    exit(EXIT_FAILURE);
                }
                poz_dir_carantina = i + 1;
                printf("Quarantine directory - %s created successfuly!\n\n", quaratine_dir);
            }

            /// verificam daca argumentul dupa -x este director
           if (lstat(argv[i + 1], &sb) < 0){
                perror("Quaratine director test error");
                exit(EXIT_FAILURE);
           }
           else{
                if(!S_ISDIR(sb.st_mode)){
                    fprintf(stderr,"%s is not a directory\n", argv[i + 1]);
                    exit(EXIT_FAILURE);
                }
           }

            /// Daca am ajuns aici sigur i + 1 este quaratine directory si exista
            poz_dir_carantina = i + 1;
        }

    }

    /// Snapshot pentru fiecare director in output
    for (i = 1; i < argc; i++){

        /// Nu are sens sa facem snapshot pe directorul de output
        if ( (i == poz_dir_output) || (i == poz_dir_output - 1) || (i == poz_dir_carantina) || (i == poz_dir_carantina - 1)){
            continue;
        }

        /// Lstat citim datele lui argv[i] in stat (detalii in man 2 lstat / lab 4)
        //struct stat stat;

        if (lstat(argv[i], &sb) < 0){
            perror("lstat");
            exit(EXIT_FAILURE);
        }

        /// Din stat extragem st_mode si folosim un macro pt a verifica daca este un director (lab 4 jos de tot)
        if (!S_ISDIR(sb.st_mode)){
            fprintf(stderr, "(Main) %s is not a directory\n", argv[i]);
        }
        else{
            /// Daca am ajuns aici stim ca argv[i] este director
            /// Creem un proces nou
            int pid = fork();

            if (pid < 0){
                perror("The fork failed!");
                exit(EXIT_FAILURE);
            }
            else if (pid == 0){

                /// Sunt in procesul copil
                create_snapshot(argv[i], argv[poz_dir_output]);

                /// Dupa ce imi fac snapshotul ies din procesul copil deoarece nu doresc sa prelucrez argumentele mai departe
                /// doar cel curent, daca este director
                exit(0);
            }
            
        }

        
    }

    int status;
    int pid_copil;
    int process_number = 0;

    do {
        /// -1 pentru ca asteptam pentru orice process fiu
        pid_copil = waitpid(-1, &status, 0);

        if (pid_copil == -1) {
            /// Nu mai avem procese fiu de asteptat
            break;
        }

        /// S-a terminat procesul fiu si afisam PID si statusul la exit
        if (WIFEXITED(status)) {
            printf("Child process %d terminated with PID %d and exit code %d\n", ++process_number, pid_copil, WEXITSTATUS(status));
        }

    } while (1) ;

    return 0;
}