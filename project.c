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


#define MAX_FILENAME_LEN 512
#define BUFFER_SIZE 2048

char dir_carantina[MAX_FILENAME_LEN] = {0};
char dir_output[MAX_FILENAME_LEN] = {0};


/// Structura pentru metadatele necesare unui snapshot
typedef struct {
    char name[MAX_FILENAME_LEN];
    ino_t inode;
    off_t size;
    time_t mtime;
    nlink_t nlinks;
    char permissions[10];
} FileMetadata;

int create_snapshot(const char *dirname, const char *output_dir);
int create_recursive_snapshot(const char *dirname, int snapshot_fd);
int get_file_metadata(const char *filename, FileMetadata *metadata);
void cleanQuarantine();
void moveToQuarantine(char *source_path, char *dest_path);


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

int create_snapshot(const char *dirname_fp, const char *output_dir) {

    char snapshot_name[MAX_FILENAME_LEN];
    char temporary_snapshot[MAX_FILENAME_LEN];
    char old_snapshot_name[MAX_FILENAME_LEN];

    /// Se face parsare in caz ca argumentul este transmis cu "/" ex: dir1/
    char dirname[MAX_FILENAME_LEN] = {0};
    strncpy(dirname, dirname_fp, MAX_FILENAME_LEN - 1);
    if (dirname[strlen(dirname) - 1] == '/'){
        dirname[strlen(dirname) - 1] = 0;
    }

    int fisiere_suspecte = 0;

    /// Se modifica cu inode number... in loc de nume dir
    struct stat d_dirname;

    if (lstat(dirname, &d_dirname) == -1) {
        perror("(create_snapshot) - inode - lstat error \n");
        exit(EXIT_FAILURE);
    }

    snprintf(snapshot_name, MAX_FILENAME_LEN, "%s/%lu.snapshot", output_dir, d_dirname.st_ino);
    snprintf(temporary_snapshot, MAX_FILENAME_LEN, "%s/%lu.snapshot_temp", output_dir, d_dirname.st_ino);
    snprintf(old_snapshot_name, MAX_FILENAME_LEN, "%s/%lu.snapshot_old", output_dir, d_dirname.st_ino);

    // Verificam daca avem deja un snapshot existent
    int snapshot_fd = open(snapshot_name, O_RDONLY);

    if (snapshot_fd >= 0) {

        //Avem un snapshot existent din moment ce exista fisierul
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
                close(snapshot_fd);
                exit(EXIT_FAILURE);
            }

            // Il construim cu toata ierarhia de fisiere/directoare, iar pe urma le comparam
            write(temporary_snapshot_fd, new_snapshot_text, strlen(new_snapshot_text));
            fisiere_suspecte = create_recursive_snapshot(dirname, temporary_snapshot_fd);
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

                printf("Old snapshot renamed: %s for %s\n", basename(old_snapshot_name), dirname);
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
        else{
            /// Eroare nu putem face snapshot pentru directorul argument - NU am putut obtine datele pt snapshotul de comparare
            exit(EXIT_FAILURE);
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
        int bytes_written = 0;

        if (get_file_metadata(dirname, &dir_metadata) != -1) {
            bytes_written = snprintf(metadata_text, BUFFER_SIZE, "Directory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                     dir_metadata.name, 
                     (unsigned long)dir_metadata.inode, 
                     (long)dir_metadata.size, 
                     ctime(&dir_metadata.mtime), 
                     (long)dir_metadata.nlinks, 
                     dir_metadata.permissions
                     );
            write(snapshot_fd, metadata_text, bytes_written);
        }
        else{
            /// Nu putem contrui snapshotul deoarece nu am putut obtine metadatele
            exit(EXIT_FAILURE);
        }

        // Parcurgem ierarhia subarborelui director
        fisiere_suspecte = create_recursive_snapshot(dirname, snapshot_fd);
        close(snapshot_fd);

        printf("Snapshot created successfully for directory: %s\n", dirname);
    }

    return fisiere_suspecte;
}



/// Scriere intreaga a ierarhii de directoare inc. subdir
int create_recursive_snapshot(const char *dirname, int snapshot_fd) {
    // Parcurge directoarele din directorul curent
    DIR *dir = opendir(dirname);
    if (dir == NULL) {
        perror("Error opening directory");
        return 0;
    }

    struct dirent *entry;
    int pipefd[2];
    char pipe_buffer[512]={0};
    static int fisiere_suspecte = 0;

    strcpy(pipe_buffer,"");

    while ((entry = readdir(dir)) != NULL) {

        if (pipe(pipefd) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }

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
            int bytes_written = 0;

            if (S_ISDIR(element.st_mode)) {
                // Dacă este subdirector, creează snapshot-ul pentru subdirector recursiv
                bytes_written = snprintf(metadata_text, BUFFER_SIZE,"Subdirectory: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, bytes_written); // Adăugăm metadatele subdirectorului la snapshot
                bytes_written = 0;

                // Creăm snapshot-ul pentru subdirector recursiv
                create_recursive_snapshot(subdir_path, snapshot_fd);

            } 
            else if (S_ISREG(element.st_mode)) {
                // +Verificare daca este fisier suspect
                // nepot - fiu - pipe
                // fiu - parinte - cod retur
                // ....
                if (!(element.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))){
                    //Avem posibilitate de fisier malitios

                    /// fiul citeste, nu scrie
                    int nepot = fork();

                    if (nepot < 0){
                        perror("Fork failed in child\n");
                        exit(EXIT_FAILURE);
                    } 
                    else if( nepot == 0){
                        /// In nepot facem verificarea de fiser malitios

                        /// Facem redirectarea pipului de write cu stdout ca acolo scriem
                        dup2(pipefd[1], 1);
                        close(pipefd[1]);
                        close(pipefd[0]);

                        execlp("./verify.sh", "./verify.sh", metadata.name, NULL);
                    }
                    else{
                        /// fiul asteapta dupa nepot
                        //sleep(1);
                        int nepot_status;
                        close(pipefd[1]);

                        /// Problema in wait ul pt nepot
                        if ( wait(&nepot_status) < 0){
                            perror("Nepot problem\n");
                            exit(EXIT_FAILURE);
                        }

                        if (WIFEXITED(nepot_status)){

                            read(pipefd[0],pipe_buffer,sizeof(pipe_buffer));
                            close(pipefd[0]);

                            /// Bugfix caractere NON_ASCII IN PIPE
                            if (strstr(pipe_buffer,"SAFE")){
                                pipe_buffer[4] = 0;
                            }

                            printf("Pipe Buffer:%s\n", pipe_buffer);

                            /// Pe scurt putem face ++ sau sa adunam ce scriptul trimite la exit (1 la exit daca e rau fisierul sau 0 daca e ok)
                            if (strcmp(pipe_buffer,"SAFE") != 0 ){

                                //fisiere_suspecte += WIFEXITED(nepot_status);
                                fisiere_suspecte++;

                                /// Mutam fisireul malitios in fisierul carantina
                                moveToQuarantine(pipe_buffer, dir_carantina);

                                memset(pipe_buffer, 0, sizeof(pipe_buffer));
                                continue;
                            }
                            else{
                                memset(pipe_buffer, 0, sizeof(pipe_buffer));
                            }

                        }
                    }

                }

                // Dacă este fișier, obține metadatele și le scrie în snapshot
                bytes_written = snprintf(metadata_text, BUFFER_SIZE, "File: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, bytes_written); // Adăugăm metadatele fișierului la snapshot
                bytes_written = 0;

            }
            else if(S_ISLNK(element.st_mode)){

                bytes_written = snprintf(metadata_text, BUFFER_SIZE, "Link: %s\nInode: %lu\nSize: %ld\nModification time: %sNumber of links: %ld\nPermissions: %s\n\n",
                                        metadata.name, 
                                        (unsigned long)metadata.inode, 
                                        (long)metadata.size, 
                                        ctime(&metadata.mtime), 
                                        (long)metadata.nlinks, 
                                        metadata.permissions
                                );
                write(snapshot_fd, metadata_text, bytes_written); // Adăugăm metadatele fișierului la snapshot
                bytes_written = 0;
            }
        }
    }

    closedir(dir);
    return fisiere_suspecte;
}

void cleanQuarantine(){

    char command[64];
    int pid_clean;
    int status;

    printf("Cleaning %s for new usage...\n\n", dir_carantina);
    sleep(1);

    snprintf(command, 63, "rm -rf %.*s/*", (int)strlen(dir_carantina), dir_carantina);

    pid_clean = fork();

    if (pid_clean < 0){

        perror("(cleanQuarantine) Fork failed");
    }
    else if (pid_clean == 0){
        /// Copil
        if ( execl("/bin/sh", "sh", "-c", command, (char *) 0) == -1){
            
            perror("(cleanQuarantine) Cleaning failed to begin!");
        }
    }
    else{
        /// Parinte
        if (wait(&status) == -1){
            perror("(cleanQuarantine) wait error");
            return;
        }

        if(!WIFEXITED(status)){
            perror("(cleanQuarantine) Cleaning process failed!");
        }
    }

}

void moveToQuarantine(char *source_path, char *dest_path){

    int pid_move;
    int status;

    char command[512]={0};
    snprintf(command, 511, "mv ./%s ./%.*s", source_path, (int)strlen(dest_path), dest_path);

    pid_move = fork();

    if (pid_move < 0){

        perror("(moveToQuarantine) Fork failed");
        return;
    }
    else if (pid_move == 0){
        /// Copil
        if ( execl("/bin/sh", "sh", "-c", command, (char *) 0) == -1){
            
            perror("(moveToQuarantine) Moving process failed to begin!");
            printf("Please rerun again the .exe file!");
        }
    }
    else{
        /// Parinte
        if (wait(&status) == -1){
            perror("(moveToQuarantine) wait error");
            return;
        }

        if(!WIFEXITED(status)){

            perror("(moveToQuarantine) Moving process failed!");
            printf("Please rerun again the .exe file!");
        }
        else{
            /// Construim calea catre fisireul din carantina pt a scoate permisiunile
            snprintf(command, 511, "./%.*s/%s", (int)strlen(dir_carantina), dir_carantina, basename(source_path));
            chmod(command,000);

        }
    }

}

int main(int argc, char *argv[]){

    /// Verificare numar argumente
    if (argc < 3 || argc > 13){

        fprintf(stderr, "Invalid number of arguments!\n Usage: %s <dir_name_0> ... -o <output_dir> ... -x <izolation_dir_name> ... <dir_name_n>\n", argv[0]);
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
                exit(EXIT_FAILURE);
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

                printf("Creating output directory...\n");
                sleep(1);

                /// Nu avem director deci creem (Output_dir nume default daca nu avem output dir deja existent)
                strncpy(dir_output,argv[i + 1], MAX_FILENAME_LEN - 1);

                if (mkdir(dir_output, 0755) == -1){

                    perror("Couldn't create output directory! - rerun .exe file");
                    exit(EXIT_FAILURE);
                }

                poz_dir_output = i + 1;
                printf("Output directory - %s created successfuly!\n", dir_output);
                sleep(1);
                continue;
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

            /// Construim calea catre directorul output
            snprintf(dir_output, MAX_FILENAME_LEN, argv[poz_dir_output]);
        }

        /// ########## SE POATE MODULARIZA ############
        /// Verificare director de carantina
        if (strcmp("-x", argv[i]) == 0){

            if (i + 1 >= argc){
                fprintf(stderr,"No quarantine directory can be found along the arguments\n");
                exit(EXIT_FAILURE);
            }

             /// Verificam daca avem flaguri de output consecutive -x -x -x 
            if (strcmp(argv[i + 1],"-x") == 0){
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

                printf("Creating quarantine directory...\n");
                sleep(1);
                /// Nu avem director deci creem (quaratine_dir nume default daca nu avem quarantine dir deja existent)

                strncpy(dir_carantina,argv[i + 1], MAX_FILENAME_LEN - 1);

                if (mkdir(dir_carantina, 0755) == -1){

                    perror("Couldn't create quarantine directory!");
                    exit(EXIT_FAILURE);
                }

                poz_dir_carantina = i + 1;
                printf("Quarantine directory - %s created successfuly!\n", dir_carantina);
                continue;
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
            
            /// Construim calea catre directorul carantina
            snprintf(dir_carantina, MAX_FILENAME_LEN, argv[poz_dir_carantina]);
        }

    }
    
    if (poz_dir_output == -1){
        
        poz_dir_output = 0; /// 0 Doar daca nu a fost specificat
        /// Verificam daca acesta exita deja
        if (lstat("default_output", &sb) < 0){
            
            ///Nu exista deci il creem
            printf("No output directory specified, creating the default output directory...\n");
            sleep(1);

            if (mkdir("default_output", 0755) == -1){

                perror("Couldn't create quarantine directory!");
                exit(EXIT_FAILURE);
            }
        }

        /// Construim calea default indiferent daca avem default sau nu pt ca se creaza sau e deja creat
        snprintf(dir_output, sizeof("default_output"), "default_output");
    }

    /// Nu a fost specificat un director carantina, deci se creeaza unul default
    if (poz_dir_carantina == -1){
        
        poz_dir_carantina = 0; /// 0 Doar daca nu a fost specificat
        /// Verificam daca acesta exita deja
        if (lstat("default_izolating", &sb) < 0){
            
            ///Nu exista deci il creem
            printf("No quarantine directory specified, creating the default quarantine directory...\n");
            sleep(1);

            if (mkdir("default_izolating", 0755) == -1){

                perror("Couldn't create quarantine directory!");
                exit(EXIT_FAILURE);
            }
        }

        /// Construim calea default indiferent daca avem default sau nu pt ca se creaza sau e deja creat
        snprintf(dir_carantina, sizeof("default_izolating"), "default_izolating");
    }

    cleanQuarantine();

    printf("Processing directories...\n");
    sleep(1);
    printf("=======================================================================================\n");

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
                int nr_fisiere = 0;
                nr_fisiere = create_snapshot(argv[i], dir_output);

                /// Dupa ce imi fac snapshotul ies din procesul copil deoarece nu doresc sa prelucrez argumentele mai departe
                /// doar cel curent, daca este director
                exit(nr_fisiere);
            }
            
        }
    }

    int status;
    int pid_copil;
    int process_number = 0;

    do {
        pid_copil = wait(&status);

        if (pid_copil == -1) {

            /// Aici a crapat comanda
            if(errno != ECHILD){
                perror("Waitpid error");
                exit(EXIT_FAILURE);
            }

            /// Nu mai avem procese fiu de asteptat
            break;
        }

        /// S-a terminat procesul fiu si afisam PID si statusul la exit
        if (WIFEXITED(status)) {
            printf("Child process %d terminated with PID %d and with %d potential dangerous files\n", ++process_number, pid_copil, WEXITSTATUS(status));
            printf("-------------------------------------------------------------------------------------\n");
        }

    } while (1) ;

    printf("=======================================================================================\n");
    return 0;
}