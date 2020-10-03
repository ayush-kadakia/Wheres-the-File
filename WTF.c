#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h>
#include <string.h> 
#include <stdlib.h>
#include <sys/types.h> 
#include <sys/stat.h>
#include <sys/mman.h> 
#include <dirent.h> 
#include <fcntl.h>
#include <libgen.h>
#include <openssl/md5.h> 

#define PORTNO 9123

typedef struct node{ 
    char* path;
    int versionno;
    unsigned char* md5hash; 
    struct node* next;
} node;

int port;
//char* clientNo;
char* ip;
char* buffer2; 
char* buffer;
int projver;
int serverver;
int manFiles = 0;
node* front;
node* front2;
int csfd;
struct sockaddr_in server_addr;

void insertFile(char* path, int version, unsigned char* hash);
unsigned char *md5_for_file(char *filename);
void insertServerFile(char* path, int version, unsigned char* hash);
node* contains(char* path);
void configure(char* ipaddr, char* portno, char* clientFolder);



void freeLL(node* front){
    node* ptr = front;
    while(ptr != NULL){
        free(ptr->md5hash);
        free(ptr->path);
        node* temp = ptr;
        ptr = ptr->next;
        free(temp);
    }
}

void insertBuffer(int fileSize, char* buf){
    int i;
    int j = 0;
    int type = 0;
    for(i = 0; i < fileSize; i++){
        if(buf[i] == '\n'){
            if(i != j){
                int currlen = (i - j) + 1;
                char curr[currlen];
                int k;
                for(k = j; k < i; k++){
                    curr[k-j] = buf[k];
                }
                curr[currlen - 1] = '\0';;
                manFiles++;
                char* temp = strtok(curr, "\t");
                char path[strlen(temp) + 1];
                strcpy(path, temp);
                path[strlen(temp)] = '\0';
                char* temp2 = strtok(NULL, "\t");
                char version[strlen(temp2) + 1];
                strcpy(version, temp2);
                version[strlen(temp2)] = '\0';
                int ver = atoi(version); 
                char* temp3 = strtok(NULL, "\t");
                char hash[strlen(temp3) + 1];
                strcpy(hash, temp3);
                hash[strlen(temp3)] = '\0';
                insertFile(path, ver, hash);
                memset(curr, '\0', strlen(curr));
            }
            j = i + 1;
        }
    }
    // if(j < fileSize){
    //     int k;
    //     char curr[(fileSize - j) + 1];
    //     for(k = j; k < fileSize; k++){
    //         curr[k-j] = buf[k];
    //     }
    //     curr[(fileSize - j)] = '\0';
    //     insertFileName(curr);
    //     manFiles++;
    //     memset(curr, '\0', strlen(curr));
    // }
}

void insertServerBuffer(int fileSize, char* buf){
    int i;
    int j = 0;
    int type = 0;
    for(i = 0; i < fileSize; i++){
        if(buf[i] == '\n'){
            if(i != j){
                int currlen = (i - j) + 1;
                char curr[currlen];
                int k;
                for(k = j; k < i; k++){
                    curr[k-j] = buf[k];
                }
                curr[currlen - 1] = '\0';;
                //manFiles++;
                char* temp = strtok(curr, "\t");
                char path[strlen(temp) + 1];
                strcpy(path, temp);
                path[strlen(temp)] = '\0';
                char* temp2 = strtok(NULL, "\t");
                char version[strlen(temp2) + 1];
                strcpy(version, temp2);
                version[strlen(temp2)] = '\0';
                int ver = atoi(version); 
                char* temp3 = strtok(NULL, "\t");
                char hash[strlen(temp3) + 1];
                strcpy(hash, temp3);
                hash[strlen(temp3)] = '\0';
                insertServerFile(path, ver, hash);
                memset(curr, '\0', strlen(curr));
            }
            j = i + 1;
        }
        
    }
    // if(j < fileSize){
    //     int k;
    //     char curr[(fileSize - j) + 1];
    //     for(k = j; k < fileSize; k++){
    //         curr[k-j] = buf[k];
    //     }
    //     curr[(fileSize - j)] = '\0';
    //     insertFileName(curr);
    //     manFiles++;
    //     memset(curr, '\0', strlen(curr));
    // }
}

void LLtoManifest(char* pathToManifest){
    int length = getListLen(front);
    node* ptr = front;
    char command[strlen(pathToManifest) + 8];
    strcpy(command, "rm -rf ");
    strcat(command, pathToManifest);
    command[strlen(pathToManifest) + 7] = '\0';
    system(command);
    int fp = open(pathToManifest, O_WRONLY | O_CREAT | O_APPEND, 00600);
    char pver[4];
    memset(pver, 0, sizeof(pver));
    snprintf(pver, sizeof(projver), "%d", projver);
    write(fp, pver, strlen(pver));
    write(fp, "\n", sizeof(char));

    while(ptr != NULL){
        write(fp, ptr->path, strlen(ptr->path));
        write(fp, "\t", sizeof(char));
        char pver2[4];
        memset(pver2, 0, sizeof(pver2));
        snprintf(pver2, sizeof(ptr->versionno), "%d", ptr->versionno);
        write(fp, pver2, strlen(pver2));
        write(fp, "\t", sizeof(char));
        write(fp, ptr->md5hash, strlen(ptr->md5hash));
        write(fp, "\n", sizeof(char));
        ptr = ptr->next;     
    }
    close(fp);
}

void configure(char* ipaddr, char* portno, char* clientFolder){
    char fullPath[strlen(clientFolder) + strlen("/.configure") + 1];
    strcpy(fullPath, clientFolder);
    strcat(fullPath, "/.configure");
    fullPath[strlen(clientFolder) + strlen("/.configure")] = '\0';
    int fp = open(fullPath, O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, ipaddr, strlen(ipaddr) * sizeof(char));
    write(fp, "\n", 1);
    write(fp, portno, strlen(portno));
    close(fp);

}

void getConfig(char* path){
    int fp = open(path, O_RDONLY);
    int fileSize;
    if(fp == -1){
        printf("Error: .configure file does not exist.\n");
        exit(0);
    }
    struct stat s;
    if(stat(path, &s) == 0)
        fileSize = s.st_size;
    else
        fileSize = -1;
    if(fileSize > 0){
        char cb[fileSize + 1];
        read(fp, cb, fileSize);
        cb[fileSize] = '\0';
        int i;
        int j; //position of first character after newline in .config
        for(i = 0; i < fileSize; i++){
            if(cb[i] == '\n'){
                char curr[(i) + 1];
                int k;
                for(k = 0; k < i; k++){
                    curr[k] = cb[k];
                }
                curr[i] = '\0';
                ip = malloc(strlen(curr));
                strcpy(ip, curr);
                memset(curr, '\0', strlen(curr));
                j = i + 1;
            }
        }
        int k;
        char curr[(fileSize - j) + 1];
        for(k = j; k < fileSize; k++){
            curr[k-j] = cb[k];
        }
        curr[fileSize - j] = '\0';
        port = atoi(curr);
        memset(curr, '\0', strlen(curr));
    }
    close(fp);
}

void clientConnect(){
    csfd = socket(AF_INET, SOCK_STREAM, 0);
    if(csfd < 0){
         printf("Error when creating client socket.\n");
         exit(0);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    int addrCheck = inet_pton(AF_INET, ip, &server_addr.sin_addr);
    if(addrCheck < 0){
        printf("Invalid address\n");
        exit(0);
    }
    int cCheck = connect(csfd, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr));
    if(cCheck < 0){
        printf("Connect failed. cCheck: %d\n", cCheck);
        exit(0);
    }
    printf("Client connected to server successfully.\n");
}

void create(char* projectName){
    //first check on the server if the project exists, if it does fail
    //send proj name length to server
    int plen = strlen(projectName);
    send(csfd, &plen, sizeof(int), 0);

    //send project name to server
    send(csfd, projectName, strlen(projectName), 0);
     
    //recv a 0 or 1 back indicating whether it exists or not
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);

    //if check is 1, the project exists --> error
    if(check == 1){
        printf("Error: Project %s already exists\n", projectName);
        exit(0);
    }

    //else make the project
    char command[strlen(projectName) + 22];
    strcpy(command, "mkdir ./client_folder/");
    strcat(command, projectName);
    command[strlen(projectName) + 22] = '\0';
    system(command);
    
    //recv manifest size from server
    int manifestSize;
    recv(csfd, &manifestSize, sizeof(int), MSG_WAITALL);

    //recv generated manifest from server
    char manifest[manifestSize + 1];
    recv(csfd, manifest, sizeof(char) * manifestSize, MSG_WAITALL);
    manifest[manifestSize] = '\0';
    
    //store the manifest into local project folder
    char manpath[strlen(projectName) + 27];
    strcpy(manpath, "./client_folder/");
    strcat(manpath, projectName);
    manpath[strlen(projectName) + 16] = '\0';
    strcat(manpath, "/.Manifest");
    manpath[26 + strlen(projectName)] = '\0';
    int fp = open(manpath, O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, manifest, manifestSize);

    //free stuff
    close(fp);
}

void destroy(char* projectName){
    int namelen = strlen(projectName);
    send(csfd, &namelen, sizeof(int), 0);

    //send project name to server
    send(csfd, projectName, strlen(projectName), 0);

    //recv 0 or 1 based on whether project was destroyed
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);

    if(check == 0)
        printf("Error: Project %s did not exist on server.\n", projectName);
    else
        printf("Project %s destroyed.\n", projectName);
}

void extractManifest(char* manipath){
    int fp = open(manipath, O_RDONLY);
    int filesize;
    struct stat s;
    int sub = 0;
    if(stat(manipath, &s) == 0)
        filesize = s.st_size;
    else
        filesize = -1;
    if(filesize != -1 && filesize >= 2){
        char dump;
        char* word = malloc(sizeof(char) * 2);
        memset(word, '\0', 2);
        while(dump != '\n'){
            sub += read(fp, &dump, 1);
            if(dump == '\n'){
                projver = atoi(word);
                free(word);
                break;
            }
            else{
                int last = strlen(word) + 1;
                char temp[strlen(word)];
                strcpy(temp, word);
                free(word);
                word = malloc (last * sizeof(char));
                memcpy(word, temp, strlen(temp));
                char fixer[2];
                fixer[0] = dump;
                fixer[1] = '\0';
                strcat(word, fixer);
            }
        }
        char buf[(filesize - sub) + 1];
        read(fp, buf, (filesize - sub));
        buf[(filesize - sub)] = '\0';
        insertBuffer(filesize, buf);
    }
    close(fp);
}

void extractServerManifest(char* manipath){
    int fp = open(manipath, O_RDONLY);
    int filesize;
    struct stat s;
    if(stat(manipath, &s) == 0)
        filesize = s.st_size;
    else
        filesize = -1;
    if(filesize != -1 && filesize >= 2){
        char dump;
        int sub = 0;
        char* word = malloc(sizeof(char) * 2);
        memset(word, '\0', 2);
        while(dump != '\n'){
            sub += read(fp, &dump, 1);
            if(dump == '\n'){
                serverver = atoi(word);
                free(word);
                break;
            }
            else{
                int last = strlen(word) + 1;
                char temp[strlen(word)];
                strcpy(temp, word);
                free(word);
                word = malloc (last * sizeof(char));
                memcpy(word, temp, strlen(temp));
                char fixer[2];
                fixer[0] = dump;
                fixer[1] = '\0';
                strcat(word, fixer);
            }
        }
        int bufsize = filesize - sub;
        char buf[bufsize + 1];
        read(fp, buf, bufsize);
        buf[bufsize] = '\0';;
        insertServerBuffer(filesize, buf);
    }
    close(fp);
}

void add(char* projectName, char* fileName){
    //check if the project exists, else fail
    int pathlen = strlen(projectName) + strlen(fileName) + 2;
    char path[pathlen];
    strcpy(path, projectName);
    path[strlen(projectName)] = '\0';
    strcat(path, "/");
    strcat(path, fileName);
    path[pathlen - 1] = '\0';

    char fullpath[pathlen + 17];
    strcpy(fullpath, "./client_folder/");
    strcat(fullpath, path);
    fullpath[pathlen + 16] = '\0';

    char projpath[17 + strlen(projectName)];
    strcpy(projpath, "./client_folder/");
    strcat(projpath, projectName);
    projpath[16 + strlen(projectName)] = '\0';

    char manpath[strlen(projectName) + 27];
    strcpy(manpath, "./client_folder/");
    strcat(manpath, projectName);
    manpath[strlen(projectName) + 16] = '\0';
    strcat(manpath, "/.Manifest");
    manpath[26 + strlen(projectName)] = '\0';

    DIR* d = opendir(projpath);
    if(d == NULL){
        printf("Error: project %s does not exist on the client.\n", projectName);
        exit(0);
    }
    closedir(d);

    extractManifest(manpath);

    if(contains(path) != NULL){
        printf("Error: file %s has already been added.\n", path);
        exit(0);
    }

    //update the manifest file to reflect changes
    unsigned char* result =  md5_for_file(fullpath);
    result[MD5_DIGEST_LENGTH] = '\0';
    int hashLen = MD5_DIGEST_LENGTH*2;
    char hex[hashLen+1];
    memset(hex, '\0', hashLen+1);

    int x = 0;
    int i = 0;

    while(x < MD5_DIGEST_LENGTH){
        snprintf((char*)(hex+i),3,"%02x", result[x]);
        x+=1;
        i+=2;
    }


    //add to manifest

    int fp = open(manpath, O_WRONLY | O_APPEND);

    write(fp, path, strlen(path));
    write(fp, "\t", strlen("\t"));
    write(fp, "1", strlen("1"));
    write(fp, "\t", strlen("\t"));
    write(fp, hex, strlen(hex));
    write(fp, "\n", strlen("\n"));

    close(fp);
}

 unsigned char *md5_for_file(char *filename) {
    int file_descript;
    unsigned long file_size;
    char *file_buffer;
    unsigned char *result = malloc(sizeof(*result) * MD5_DIGEST_LENGTH);

    file_descript = open(filename, O_RDONLY);
    if (file_descript < 0) exit(-1);

    struct stat statbuf;
    if (fstat(file_descript, &statbuf) < 0) exit(-1);

    file_size = statbuf.st_size;

    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    MD5((unsigned char *) file_buffer, file_size, result);
    munmap(file_buffer, file_size);

    close(file_descript);
    return result;
}

void gitremove(char* projectName, char* fileName){
    char filepath[strlen(projectName) + strlen(fileName) + 2];
    strcpy(filepath, projectName);
    filepath[strlen(projectName)] = '/';
    filepath[strlen(projectName) + 1] = '\0';
    strcat(filepath, fileName);
    filepath[strlen(projectName) + strlen(fileName) + 1] ='\0';

    //after getting the filepath, open and extract the manifest
    char manpath[strlen(projectName) + 27];
    strcpy(manpath, "./client_folder/");
    strcat(manpath, projectName);
    manpath[strlen(projectName) + 16] = '\0';
    strcat(manpath, "/.Manifest");
    manpath[26 + strlen(projectName)] = '\0';
    extractManifest(manpath);
    node* ptr2 = front;

    //search for the filename in the manifest
    //if it exists, remove it from the linked list
    node* prev = NULL;
    node* ptr = front;
    while(ptr != NULL){
        if(strcmp(ptr->path, filepath) == 0){
            if(prev != NULL){
                prev->next = ptr->next;
                free(ptr->path);
                free(ptr->md5hash);
                free(ptr);
                break;
            }
            else{
                front = ptr->next;
                free(ptr->path);
                free(ptr->md5hash);
                free(ptr);
                break;
            }
        }
        prev = ptr;
        ptr = ptr->next;
    }

    //remove the file
    char rmcmd[strlen(filepath) + 19];
    strcpy(rmcmd, "rm ./client_folder/");
    strcat(rmcmd, filepath);
    system(rmcmd);
    
    //overwrite the manifest with the LL
    LLtoManifest(manpath);
    
}

void currentversion(char* projectName){
    //send projectname length to server
    int plen = strlen(projectName);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projectName, strlen(projectName), 0);
    
    //receive an indicator on whether the project exists on the server
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Error: project %s does not exist on the server.\n", projectName);
        exit(0);
    }

    //recieve the manifest file size from server
    int manifestSize;
    recv(csfd, &manifestSize, sizeof(int), MSG_WAITALL);   

    //recieve the manifest file from server
    char manifestFile[manifestSize+1];
    recv(csfd, &manifestFile, sizeof(char) * manifestSize, MSG_WAITALL);    
    manifestFile[manifestSize] = '\0';

    //put manifest contents into the LL
    int fp = open("./.tempManifest", O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, manifestFile, strlen(manifestFile));
    extractManifest("./.tempManifest");
    close(fp);

    //print the path and version no from LL
    node* ptr = front;
    while(ptr != NULL){
        printf("File: %s, Version %d\n", ptr->path, ptr->versionno);
        ptr = ptr->next;
    }
    free(ptr);

    //remove the temp manifest file
    system("rm -rf ./.tempManifest");    
}

void checkout(char* projectName){
    //send projectname length to server
    int plen = strlen(projectName);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projectName, strlen(projectName), 0);
    //recieve a 0 or 1 indicating whether the project exists
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Error: Project does not exist on the server.\n");
        exit(0);
    }

    //check client side whether the project exists
    char dircheck[17 + strlen(projectName)];
    strcpy(dircheck, "./client_folder/");
    strcat(dircheck, projectName);
    dircheck[16 + strlen(projectName)] = '\0';
    DIR* d = opendir(dircheck);
    int projcheck = 0;
    if(d != NULL){
        printf("Error: Project already exists on client\n");
        send(csfd, &projcheck, sizeof(int), 0);
        exit(0);
    }
    else{
        projcheck = 1;
        send(csfd, &projcheck, sizeof(int), 0);
    }

    closedir(d);
    
    //recieve the tar file size from server
    int tarSize;
    recv(csfd, &tarSize, sizeof(int), MSG_WAITALL); 

    //recieve the tar file from server
    char tarFile[tarSize+1];
    recv(csfd, &tarFile, sizeof(char) * tarSize, MSG_WAITALL);    
    tarFile[tarSize] = '\0';
    
    //write it to a new tar in client folder
    char projectTar[strlen(projectName) + 24];
    strcpy(projectTar, "./client_folder/");
    strcat(projectTar, projectName);
    projectTar[strlen(projectName) + 17] = '\0';
    strcat(projectTar, ".tar.gz");
    projectTar[strlen(projectName) + 24] = '\0';
    
    int fp = open(projectTar, O_WRONLY | O_APPEND | O_CREAT, 00600);
    int c = write(fp, tarFile, tarSize);

    //use system call to untar the file
    char command2[strlen(projectTar) + 9];
    strcpy(command2, "tar -xf ");
    strcat(command2, projectTar);
    command2[strlen(projectTar) + 8] = '\0';
    char command4[strlen(command2) + 21];
    strcpy(command4, command2);
    strcat(command4, " -C ./client_folder/");
    command4[strlen(command2) + 20] = '\0'; 
    system(command4);
    
    //use system call to delete the tar file
    char command3[strlen(projectTar) + 8];
    strcpy(command3, "rm -rf ");
    strcat(command3, projectTar);
    command3[strlen(projectTar) + 7] = '\0';
    system(command3);

    //free stuff
    printf("Client: Checkout Succeeded\n");
    close(fp);
}

void insertFile(char* path, int version, unsigned char* hash){
    node * temp = malloc(sizeof(node));
    temp->path = malloc(sizeof(char) * strlen(path) + 1);
    strcpy(temp->path, path);
    temp->path[strlen(path)] = '\0';
    temp->versionno = version;
    temp->md5hash = malloc(sizeof(char) * strlen(hash) + 1);
    strcpy(temp->md5hash, hash);
    temp->md5hash[strlen(hash)] = '\0';
    temp->next = NULL;
    if(front == NULL){
        front = temp;
        return;
    }
    else{
        node* ptr = front;
        while(ptr->next != NULL){
            ptr = ptr->next;
        }
        ptr->next = temp;
    }
}

void insertServerFile(char* path, int version, unsigned char* hash){
    node * temp = malloc(sizeof(node));
    temp->path = malloc(sizeof(char) * strlen(path) + 1);
    strcpy(temp->path, path);
    temp->path[strlen(path)] = '\0';
    temp->versionno = version;
    temp->md5hash = malloc(sizeof(char) * strlen(hash) + 1);
    strcpy(temp->md5hash, hash);
    temp->md5hash[strlen(hash)] = '\0';
    temp->next = NULL;
    if(front2 == NULL){
        front2 = temp;
        return;
    }
    node* ptr = front2;
    while(ptr->next != NULL)
        ptr = ptr->next;
    ptr->next = temp;
}


int getListLen(){
    int i = 0;
    node* ptr = front;
    while(ptr != NULL){
        i++;
        ptr = ptr->next;
    }
    return i;
}

node* contains(char* path){
    node* ptr = front;
    while(ptr != NULL){
        if(strcmp(ptr->path, path) == 0)
            return ptr;
        ptr = ptr->next;
    }
    return NULL;
}

node* serverContains(char* path){
    node* ptr = front2;
    int i = 1;
    while(ptr != NULL){
        if(strcmp(ptr->path, path) == 0)
            return ptr;
        ptr = ptr->next;
        i++; 
    }
    return NULL;
}

void deleteFileName(char* path){
    node * ptr = front;
    node * prev = NULL;

    if(ptr != NULL && strcmp(ptr->path, path) == 0){
        front = ptr->next;
        free(ptr);
        return;
    }

    while(ptr != NULL && strcmp(ptr->path, path) != 0){
        prev = ptr;
        ptr = ptr->next;
    }

    if(ptr == NULL)
        return;

    prev->next = ptr->next;
    free(ptr);
}


void commit(char* projname){
    //send projectname length to server
    int plen = strlen(projname);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projname, strlen(projname), 0);
    //recieve a 0 or 1 indicating whether the project exists
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Error: Project does not exist on the server.\n");
        exit(0);
    }


    char confp[strlen(projname) + 26];
    char updp[strlen(projname) + 24];
    strcpy(confp, "./client_folder/");
    strcat(confp, projname);
    strcat(confp, "/.Conflict");
    strcpy(updp, "./client_folder/");
    strcat(updp, projname);    
    strcat(updp, "/.Conflict");
    struct stat conf;
    struct stat updt;
    int confsize;
    int updtsize;
    if(stat(confp, &conf) == 0)
        confsize = conf.st_size;
    else
        confsize = -1;
    if(stat(updp, &updt) == 0)
        updtsize = updt.st_size;
    else
        updtsize = -1;
    int fcheck = 0;
    if(confsize != -1 || updtsize > 0)
        fcheck = 1;
    send(csfd, &fcheck, sizeof(int), 0);
    if(fcheck == 1){
        printf("Commit failed. Client has a .Conflict file or a non-empty .Update file.\n");
        exit(0);
    }
    //recv manifest size from server
    int manifestSize;
    recv(csfd, &manifestSize, sizeof(int), MSG_WAITALL);

    //recv generated manifest from server
    char manifest[manifestSize + 1];
    recv(csfd, manifest, sizeof(char) * manifestSize, MSG_WAITALL);
    manifest[manifestSize] = '\0';
    //create a temporary second manifest based on the server's manifest file to compare to the client's manifest
    int fp = open("./.tempManifest", O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, manifest, strlen(manifest));
    extractServerManifest("./.tempManifest");
    close(fp);
    system("rm -rf ./.tempManifest");    
    //get client-side manifest path and load into LL
    char manpath[strlen(projname) + 27];
    strcpy(manpath, "./client_folder/");
    strcat(manpath, projname);
    manpath[strlen(projname) + 16] = '\0';
    strcat(manpath, "/.Manifest");
    manpath[26 + strlen(projname)] = '\0';
    extractManifest(manpath);
    //compare the manifest version by comparing serverver and projver
    int sameCheck = 1;
    if(projver != serverver)
        sameCheck = 0;
    send(csfd, &sameCheck, sizeof(int), 0);
    if(sameCheck == 0){
        printf("Commit failed. Client and server project versions do not match.\n");
        exit(0);
    }

    char hpath[strlen(projname) + 27];
    strcpy(hpath, "./client_folder/");
    strcat(hpath, projname);
    strcat(hpath, "/.cHistory");
    hpath[strlen(projname) + 26] = '\0';
    int fp4 = open(hpath, O_WRONLY | O_CREAT | O_TRUNC, 00600);
    char verStr[4];
    memset(verStr, 0, sizeof(verStr));
    snprintf(verStr, sizeof(projver), "%d", projver);
    char histVersion[strlen(verStr) + 14];
    strcpy(histVersion, "Version ");
    strcat(histVersion, verStr);
    strcat(histVersion, " push\n");
    write(fp4, histVersion, strlen(histVersion) * sizeof(char));
    
    //make the .commit file
    char compath[strlen(projname) + 25];
    strcpy(compath, "./client_folder/");
    strcat(compath, projname);
    compath[strlen(projname) + 16] = '\0';
    strcat(compath, "/.Commit");
    compath[24 + strlen(projname)] = '\0';
    int fp2 = open(compath, O_WRONLY | O_CREAT | O_TRUNC, 00600);

    node* cptr = front;
    while(cptr != NULL){
        node* sloc = serverContains(cptr->path);
        if(sloc != NULL){
            char fullpath[17 + strlen(cptr->path)];
            strcpy(fullpath, "./client_folder/");
            strcat(fullpath, cptr->path);
            fullpath[16 + strlen(cptr->path)] = '\0';
            unsigned char* livehash = md5_for_file(fullpath);
            //convert livehash to hex format
            livehash[MD5_DIGEST_LENGTH] = '\0';
            int hashLen = MD5_DIGEST_LENGTH*2;
            char livehashstr[hashLen+1];
            memset(livehashstr, '\0', hashLen+1);

            int x = 0;
            int i = 0;

            while(x < MD5_DIGEST_LENGTH){
                snprintf((char*)(livehashstr+i),3,"%02x", livehash[x]);
                x+=1;
                i+=2;
            }

            if(strcmp(livehashstr, sloc->md5hash) != 0){
                write(fp2, "M", strlen("M") * sizeof(char));
                write(fp2, "\t", strlen("\t") * sizeof(char));
                write(fp2, cptr->path, strlen(cptr->path));
                write(fp2, "\t", strlen("\t") * sizeof(char));
                write(fp2, livehashstr, strlen(livehashstr) * sizeof(char));
                write(fp2, "\t", strlen("\t") * sizeof(char));
                char incpver[4];
                memset(incpver, 0, sizeof(incpver));
                int actincpver = cptr->versionno+1;
                snprintf(incpver, sizeof(incpver), "%d", actincpver);
                write(fp2, incpver, strlen(incpver));               
                write(fp2, "\n", strlen("\n") * sizeof(char));
                char action[strlen(cptr->path) + 4];
                strcpy(action, "M ");
                strcat(action, cptr->path);
                strcat(action, "\n");
                action[strlen(cptr->path) + 3] = '\0';
                printf("%s\n", action);
                write(fp4, action, strlen(action) * sizeof(char));
                cptr->versionno = actincpver;
                //memset(cptr->md5hash, '\0', strlen(cptr->md5hash));
                strcpy(cptr->md5hash, livehashstr);
            }
        }
        else{
            write(fp2, "A", strlen("A") * sizeof(char));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, cptr->path, strlen(cptr->path));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, cptr->md5hash, strlen(cptr->md5hash));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            char pver[4];
            memset(pver, 0, sizeof(pver));
            snprintf(pver, sizeof(cptr->versionno), "%d", cptr->versionno);
            write(fp2, pver, strlen(pver));               
            write(fp2, "\n", strlen("\n") * sizeof(char));
            char action[strlen(cptr->path) + 4];
            strcpy(action, "A ");
            strcat(action, cptr->path);
            strcat(action, "\n");
            action[strlen(cptr->path) + 3] = '\0';
            printf("%s\n", action);
            write(fp4, action, strlen(action) * sizeof(char));
        }
        cptr = cptr->next;
    }


    node* sptr = front2;
    while(sptr != NULL){
        node* cloc = contains(sptr->path);
        if(cloc == NULL){
            write(fp2, "R", strlen("R") * sizeof(char));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, sptr->path, strlen(sptr->path));  
            write(fp2, "\t", strlen("\t") * sizeof(char));         
            write(fp2, sptr->md5hash, strlen(sptr->md5hash));
            write(fp2, "\t", strlen("\t") * sizeof(char)); 
            write(fp2, "0", strlen("0") * sizeof(char));             
            write(fp2, "\n", strlen("\n") * sizeof(char));
            char action[strlen(sptr->path) + 4];
            strcpy(action, "D ");
            strcat(action, sptr->path);
            strcat(action, "\n");
            action[strlen(sptr->path) + 3] = '\0';
            printf("%s\n", action);
            write(fp4, action, strlen(action) * sizeof(char));
        }
        sptr = sptr->next;
    }
    close(fp);
    close(fp2);
    close(fp4);
    
    int fileSize;
    int fp3 = open(compath, O_RDONLY);
    if(fp != -1){
        struct stat s;
        if(stat(compath, &s) == 0)
            fileSize = s.st_size;
        else
            fileSize = -1;
        send(csfd, &fileSize, sizeof(int), 0);
        if(fileSize > 0){
            char commit[fileSize + 1];
            read(fp, commit, fileSize);
            commit[fileSize] = '\0';
            send(csfd, commit, fileSize * sizeof(char), 0);
        }
    }
    close(fp3);

    projver = projver + 1;
    LLtoManifest("./.helper");



}

void push(char* projname){
   //send projectname length to server
    int plen = strlen(projname);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projname, strlen(projname), 0);
    //recieve a 0 or 1 indicating whether the project exists
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Error: Project does not exist on the server.\n");
        exit(0);
    }
    int commitsize;
    recv(csfd, &commitsize, sizeof(int), MSG_WAITALL);
    if(commitsize == -1){
        printf("Push failed. .Commit file for project %s does not exist on the server.\n", projname);
        exit(0);
    }
    //create an md5 hash of the commit file
    char commitpath[strlen(projname) + 25];
    strcpy(commitpath, "./client_folder/");
    commitpath[strlen("./client_folder/")] = '\0';
    strcat(commitpath, projname);
    commitpath[strlen("./client_folder/") + strlen(projname)] = '\0';
    strcat(commitpath, "/.Commit");
    commitpath[strlen(projname) + 24] = '\0';

    unsigned char* result =  md5_for_file(commitpath); 
    result[MD5_DIGEST_LENGTH] = '\0';
    int hashLen = MD5_DIGEST_LENGTH*2;
    char hex[hashLen+1];
    memset(hex, '\0', hashLen+1);

    int x = 0;
    int i = 0;

    while(x < MD5_DIGEST_LENGTH){
        snprintf((char*)(hex+i),3,"%02x", result[x]);
        x+=1;
        i+=2;
    }

    int chashlen = strlen(hex);
    send(csfd, &chashlen, sizeof(int), 0);

    send(csfd, hex, strlen(hex) * sizeof(char), 0);

    int samecheck;
    recv(csfd, &samecheck, sizeof(int), MSG_WAITALL);

    if(samecheck == 0){
        printf("Push failed. .Commit file on server is not the same as .Commit file on client, or .Commit file on server has been overwritten by a different client.\n");
        exit(0);
    }

    char hpath[strlen(projname) + 27];
    strcpy(hpath, "./client_folder/");
    strcat(hpath, projname);
    strcat(hpath, "/.cHistory");
    hpath[strlen(projname) + 26] = '\0';
    int fp4 = open(hpath, O_RDONLY);
    struct stat s2;
    int fileSize;
    if(stat(hpath, &s2) == 0)
        fileSize = s2.st_size;
    else
        fileSize = -1;
    send(csfd, &fileSize, sizeof(int), 0);
    if(fileSize > 0){
        char cHist[fileSize + 1];
        read(fp4, cHist, fileSize);
        cHist[fileSize] = '\0';
        send(csfd, cHist, strlen(cHist) * sizeof(char), 0);
    }
    close(fp4);
    char syscmd[strlen(hpath) + 7];
    strcpy(syscmd, "rm -rf ");
    strcat(syscmd, hpath);
    system(syscmd);

    int toCheck = 1;
    int n = 0;
    int j = 0;
    int hasNewFiles = 0;
    char tarcmd[strlen(projname) + 36];
    strcpy(tarcmd, "cd ./client_folder && tar -cf ");
    strcat(tarcmd, projname);
    strcat(tarcmd, ".tar.gz ");
    int fp00 = open("./.fileCommand", O_WRONLY | O_CREAT | O_TRUNC, 00600);
    write(fp00, tarcmd, strlen(tarcmd));
    int fp10 = open(commitpath, O_RDONLY);
    char scbuffer[commitsize + 1];
    read(fp10, scbuffer, commitsize);
    scbuffer[commitsize] = '\0';
    close(fp10);     
    while(n < commitsize){
        if(toCheck == 1){
            if(scbuffer[n] == 'M' || scbuffer[n] == 'A'){
                hasNewFiles = 1;
                j = n + 2;
                n = j;
                while(scbuffer[n] != '\t'){
                    n++;
                }
                char toSend[(n - j) + 1];
                int p;
                for(p = j; p < n; p++){
                    toSend[p - j] = scbuffer[p];
                }
                toSend[n - j] = '\0';
                write(fp00, toSend, strlen(toSend) * sizeof(char));
                write(fp00, " ", strlen(" ") * sizeof(char));
            }
                
                toCheck = 0;        
        }
        else if(scbuffer[n] == '\n')
            toCheck = 1;
        n++;
    }
    close(fp00);
    send(csfd, &hasNewFiles, sizeof(int), 0);
    if(hasNewFiles == 1){
        int fp01 = open("./.fileCommand", O_RDONLY);
        struct stat s3;
        int commandSize;
        if(stat("./.fileCommand", &s3) == 0)
            commandSize = s3.st_size;

        char cmd[commandSize + 1];
        read(fp01, cmd, commandSize);
        cmd[commandSize] = '\0';
        system(cmd);
        close(fp01);
        system("rm -rf ./.fileCommand");
    
        //store the .tar in a buffer and send it over to server
        char tarpath[strlen(projname) + 24];
        memset(tarpath, '\0', strlen(tarpath));
        strcat(tarpath, "./client_folder/");
        strcat(tarpath, projname);
        strcat(tarpath, ".tar.gz");

        int fp2 = open(tarpath, O_RDONLY);
        int tarsize;
        struct stat s;
        if(stat(tarpath, &s) == 0)
            tarsize = s.st_size;
        else
            tarsize = -1;
        send(csfd, &tarsize, sizeof(int), 0);
        char buffer[tarsize + 1];
        read(fp2, buffer, tarsize);
        buffer[tarsize] = '\0';
        send(csfd, buffer, tarsize * sizeof(char), 0);
        //remove the .tar from client
        char rmvcmd[strlen(projname) + 35];
        memset(rmvcmd, '\0', strlen(rmvcmd));
        strcpy(rmvcmd, "cd client_folder && rm -rf ");
        strcat(rmvcmd, projname);
        strcat(rmvcmd, ".tar.gz");
        system(rmvcmd);
        close(fp2);
    }




    //send helper stuff

    int fp = open("./.helper", O_RDONLY);
    int fileSize2;
    if(fp != -1){
        struct stat s;
        if(stat("./.helper", &s) == 0)
            fileSize2 = s.st_size;
        else
            fileSize2 = -1;
        
        send(csfd, &fileSize2, sizeof(int), 0);
        if(fileSize > 0){
            char helper[fileSize2 + 1];
            read(fp, helper, fileSize2);
            helper[fileSize2] = '\0';
            send(csfd, helper, fileSize2 * sizeof(char), 0);
            char manpath[strlen(projname) + 27];
            memset(manpath, '\0', strlen(manpath));
            strcpy(manpath, "./client_folder/");
            strcat(manpath, projname);
            strcat(manpath, "/.Manifest");
            char syscom2[strlen(manpath) + 7];
            strcpy(syscom2, "rm -rf ");
            strcat(syscom2, manpath);
            system(syscom2);
            int fp3 = open(manpath, O_WRONLY | O_TRUNC | O_CREAT, 00600);
            write(fp3, helper, strlen(helper));
            close(fp3);
        }
    }
    close(fp);
    close(fp4);
    printf("push succeeded\n");

    char syscmd2[strlen(commitpath) + 7];
    strcpy(syscmd2, "rm -rf ");
    strcat(syscmd2, commitpath);
    system(syscmd2);
    system("rm -rf ./.helper");

}

void update(char* projName){
    //check if the file exists on the server by sending projlen and projname
   
    //send projectname length to server
    int plen = strlen(projName);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projName, strlen(projName), 0);
    //recieve a 0 or 1 indicating whether the project exists
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Update failed. Project %s does not exist on the server.\n", projName);
        exit(0);
    }

    //recv manifest size from server
    int manifestSize;
    recv(csfd, &manifestSize, sizeof(int), MSG_WAITALL);

    //recv generated manifest from server
    char manifest[manifestSize + 1];
    recv(csfd, manifest, sizeof(char) * manifestSize, MSG_WAITALL);
    manifest[manifestSize] = '\0';
    //create a temporary second manifest based on the server's manifest file to compare to the client's manifest
    int fp = open("./.tempManifest", O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, manifest, strlen(manifest));
    extractServerManifest("./.tempManifest");
    close(fp);
    system("rm -rf ./.tempManifest");    
    //get client-side manifest path and load into LL
    char manpath[strlen(projName) + 27];
    strcpy(manpath, "./client_folder/");
    strcat(manpath, projName);
    manpath[strlen(projName) + 16] = '\0';
    strcat(manpath, "/.Manifest");
    manpath[26 + strlen(projName)] = '\0';
    extractManifest(manpath);
    //compare the manifest version by comparing serverver and projver
    int verCheck = 0;
    if(projver == serverver)
        verCheck = 1;
    send(csfd, &verCheck, sizeof(int), 0);
    char updatePath[strlen(projName) + 24];
    char conflictPath[strlen(projName) + 26];
    strcpy(updatePath, "./client_folder/");
    strcat(updatePath, projName);
    strcpy(conflictPath, updatePath);
    strcat(updatePath, "/.Update");
    strcat(conflictPath, "/.Conflict");
    char removeCmd[strlen(conflictPath) + 7];
    strcpy(removeCmd, "rm -rf ");
    strcat(removeCmd, conflictPath);

    int fp2 = open(updatePath, O_WRONLY | O_APPEND | O_CREAT, 00600);
    int fp3 = open(conflictPath, O_WRONLY | O_APPEND | O_CREAT, 00600);
    //full success case
    if(projver == serverver){
        printf("Up To Date\n");
        close(fp2);
        system(removeCmd);
        exit(0);
    }
    //partial success cases
    node* sptr = front2;
    int hasConflict = 0;
    while(sptr != NULL){
        node* cloc = contains(sptr->path);
        if(cloc != NULL){
            char fullpath[17 + strlen(sptr->path)];
            strcpy(fullpath, "./client_folder/");
            strcat(fullpath, sptr->path);
            fullpath[16 + strlen(sptr->path)] = '\0';
            unsigned char* livehash = md5_for_file(fullpath);
            //convert livehash to hex format
            livehash[MD5_DIGEST_LENGTH] = '\0';
            int hashLen = MD5_DIGEST_LENGTH*2;
            char livehashstr[hashLen+1];
            memset(livehashstr, '\0', hashLen+1);

            int x = 0;
            int i = 0;

            while(x < MD5_DIGEST_LENGTH){
                snprintf((char*)(livehashstr+i),3,"%02x", livehash[x]);
                x+=1;
                i+=2;
            }

            if(strcmp(livehashstr, cloc->md5hash) == 0 && strcmp(livehashstr, sptr->md5hash) != 0 && cloc->versionno != sptr->versionno){ //modify
                write(fp2, "M", strlen("M") * sizeof(char));
                write(fp2, "\t", strlen("\t") * sizeof(char));
                write(fp2, sptr->path, strlen(sptr->path));
                write(fp2, "\t", strlen("\t") * sizeof(char));
                write(fp2, sptr->md5hash, strlen(sptr->md5hash) * sizeof(char));
                write(fp2, "\n", strlen("\n") * sizeof(char));
                cloc->versionno = sptr->versionno;
                strcpy(cloc->md5hash, sptr->md5hash);
                printf("M %s %s\n", sptr->path, sptr->md5hash);
            } //failure case
            else if(strcmp(livehashstr, cloc->md5hash) != 0 && strcmp(livehashstr, sptr->md5hash) != 0){ //conflict
                hasConflict = 1;
                write(fp3, "C", strlen("C") * sizeof(char));
                write(fp3, "\t", strlen("\t") * sizeof(char));
                write(fp3, sptr->path, strlen(sptr->path));
                write(fp3, "\t", strlen("\t") * sizeof(char));
                write(fp3, livehashstr, strlen(livehashstr) * sizeof(char));
                write(fp3, "\n", strlen("\n") * sizeof(char));
                printf("C %s\n", sptr->path);
            }
        }
        else{ //Add
            write(fp2, "A", strlen("A") * sizeof(char));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, sptr->path, strlen(sptr->path));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, sptr->md5hash, strlen(sptr->md5hash));            
            write(fp2, "\n", strlen("\n") * sizeof(char));
            printf("A %s %s\n", sptr->path, sptr->md5hash);
        }
        sptr = sptr->next;
    }

    node* cptr = front;
    while(cptr != NULL){
        node* sloc = serverContains(cptr->path);
        if(sloc == NULL){
            write(fp2, "D", strlen("D") * sizeof(char));
            write(fp2, "\t", strlen("\t") * sizeof(char));
            write(fp2, cptr->path, strlen(cptr->path));  
            write(fp2, "\t", strlen("\t") * sizeof(char));       
            write(fp2, cptr->md5hash, strlen(cptr->md5hash));        
            write(fp2, "\n", strlen("\n") * sizeof(char));
            printf("D %s\n", cptr->path);
        }
        cptr = cptr->next;
    }
    int confSize;
    struct stat s2; 
    if(stat(conflictPath, &s2) == 0)
        confSize = s2.st_size;
    else
        confSize = -1;
    if(confSize < 1)
        system(removeCmd);
    char removeUp[strlen(updatePath) + 3];
    strcpy(removeUp, "rm ");
    strcat(removeUp, updatePath);
    if(hasConflict == 1){
        printf("Conflicts have been found and must be resolved before project %s can be updated.\n", projName);
        system(removeUp);
    }
    close(fp2);
    close(fp3);
    LLtoManifest("./.helper2");
}

void upgrade(char* projName){
    //send project name length to server
    int plen = strlen(projName);
    send(csfd, &plen, sizeof(int), 0);

    //send project name to server
    send(csfd, projName, strlen(projName), 0);

    //receive 0 or 1 indicating whether project exists server side
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);

    //if check is 0, the project dne --> error
    if(check == 0){
        printf("Error: Project does not exist on server");
        exit(0);
    }
    
    //check if .conflict and update file exists with stat, if -1 exit/error
    char updatePath[strlen(projName) + 24];
    char conflictPath[strlen(projName) + 26];
    char manifestPath[strlen(projName) + 26];
    strcpy(updatePath, "./client_folder/");
    strcat(updatePath, projName);
    strcpy(conflictPath, updatePath);
    strcpy(manifestPath, updatePath);
    strcat(updatePath, "/.Update");
    strcat(conflictPath, "/.Conflict");
    strcat(manifestPath, "/.Manifest");

    struct stat s;
    struct stat s2;
    int failCheck = 0;
    if(stat(updatePath, &s) == -1 || stat(conflictPath, &s2) == 0)
        failCheck = 1;
    send(csfd, &failCheck, sizeof(int), 0);
    if(failCheck == 1){
        printf("Upgrade failed. Client does not have a .Update file or does have a .Conflict file.\n");
        exit(0);
    }
     //recv manifest size from server
    int manifestSize;
    recv(csfd, &manifestSize, sizeof(int), MSG_WAITALL);

    //recv generated manifest from server
    char manifest[manifestSize + 1];
    recv(csfd, manifest, sizeof(char) * manifestSize, MSG_WAITALL);
    manifest[manifestSize] = '\0';
    char removeManifest[strlen(manifestPath) + 7];
    strcpy(removeManifest, "rm -rf ");
    strcat(removeManifest, manifestPath);
    system(removeManifest);
    int fp = open(manifestPath, O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp, manifest, strlen(manifest));
    close(fp);

    struct stat s3;
    int updateSize;
    if(stat(updatePath, &s3) == 0)
        updateSize = s3.st_size;
    int toCheck = 1;
    int n = 0;
    int j = 0;
    int hasNewFiles = 0;
    char tarcmd[strlen(projName) + 37];
    memset(tarcmd, '\0', strlen(tarcmd));
    strcpy(tarcmd, "cd ./server_folder && tar -cf ");
    strcat(tarcmd, projName);
    strcat(tarcmd, ".tar.gz ");
    int fp3 = open("./.fileRequest", O_WRONLY | O_APPEND | O_CREAT, 00600);
    write(fp3, tarcmd, strlen(tarcmd));
    //make the tar command for the server
    int fp2 = open(updatePath, O_RDONLY);
    char scbuffer[updateSize + 1];
    read(fp2, scbuffer, updateSize);
    scbuffer[updateSize] = '\0';
    close(fp2);
    while(n < updateSize){
        if(toCheck == 1){
            if(scbuffer[n] == 'M' || scbuffer[n] == 'A'){
                hasNewFiles = 1;
                j = n + 2;
                n = j;
                while(scbuffer[n] != '\t'){
                    n++;
                }
                char toSend[(n - j) + 1];
                int p;
                for(p = j; p < n; p++){
                    toSend[p - j] = scbuffer[p];
                }
                toSend[n - j] = '\0';
                write(fp3, toSend, strlen(toSend) * sizeof(char));
                write(fp3, " ", strlen(" ") * sizeof(char));
            }
            else if(scbuffer[n] == 'D'){
                j = n + 2;
                n = j;
                while(scbuffer[n] != '\t'){
                    n++;
                }
                char toRemove[(n - j) + 1];
                int p;
                for(p = j; p < n; p++){
                    toRemove[p - j] = scbuffer[p];
                }
                toRemove[n - j] = '\0';
                char syscom[strlen(toRemove) + 23];
                strcpy(syscom, "rm -rf ./client_folder/");
                strcat(syscom, toRemove);
                system(syscom);
            }
                
                toCheck = 0;        
        }
        else if(scbuffer[n] == '\n')
            toCheck = 1;
            n++;
    }
    close(fp3);
    send(csfd, &hasNewFiles, sizeof(int), 0);
    if(hasNewFiles == 1){
        //request added/modified files from server
        int fp4 = open("./.fileRequest", O_RDONLY);
        struct stat s4;
        int commandSize;
        if(stat("./.fileRequest", &s4) == 0)
            commandSize = s4.st_size;
        send(csfd, &commandSize, sizeof(int), 0);
        char command[commandSize + 1];
        read(fp4, command, commandSize);
        command[commandSize] = '\0';
        send(csfd, command, commandSize * sizeof(char), 0);
        close(fp4);
        system("rm -rf ./.fileRequest");

        //receive files in a .tar.gz file
        char tarpath[strlen(projName) + 23];
        strcpy(tarpath, "./client_folder/");
        strcat(tarpath, projName);
        strcat(tarpath, ".tar.gz");
        int fp5 = open(tarpath, O_WRONLY | O_APPEND | O_CREAT, 00600);
        int tarsize;
        recv(csfd, &tarsize, sizeof(int), MSG_WAITALL);
        char tarfile[tarsize + 1];
        recv(csfd, tarfile, tarsize * sizeof(char), MSG_WAITALL);
        tarfile[tarsize] = '\0';
        write(fp5, tarfile, tarsize * sizeof(char));

        char cmd[strlen(projName) + 36];
        memset(cmd, '\0', strlen(cmd));
        strcpy(cmd, "cd client_folder && tar -xf ");
        strcat(cmd, projName);
        strcat(cmd, ".tar.gz");
        system(cmd);
        close(fp5);
        //remove the .tar from server
        char rmvcmd[strlen(projName) + 35];
        memset(rmvcmd, '\0', strlen(rmvcmd));
        strcpy(rmvcmd, "cd client_folder && rm -rf ");
        strcat(rmvcmd, projName);
        strcat(rmvcmd, ".tar.gz");
        system(rmvcmd); 
        
        char rmUpdate[strlen(projName) + 31];
        strcpy(rmUpdate, "cd client_folder/");
        strcat(rmUpdate, projName);
        strcat(rmUpdate, " && rm .Update");
        system(rmUpdate);
    }
}

void history(char* projectName){
    //send project name length to server
    int plen = strlen(projectName);
    send(csfd, &plen, sizeof(int), 0);

    //send project name to server
    send(csfd, projectName, strlen(projectName), 0);

    //receive 0 or 1 indicating whether project exists server side
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);

    //if check is 0, the project dne --> error
    if(check == 0){
        printf("Error: Project does not exist on server");
        exit(0);
    }

    //request history file size from server
    int historySize;
    recv(csfd, &historySize, sizeof(int), MSG_WAITALL);

    //recv history from server
    char history[historySize + 1];
    recv(csfd, history, sizeof(char) * historySize, MSG_WAITALL);
    history[historySize] = '\0';

    //print the history file buffer
    printf("%s", history); 

}

void rollback(char* projName, char* verNo){
    //send projectname length to server
    int plen = strlen(projName);
    send(csfd, &plen, sizeof(int), 0);

    //send projectname to server
    send(csfd, projName, strlen(projName), 0);
    //recieve a 0 or 1 indicating whether the project exists
    int check;
    recv(csfd, &check, sizeof(int), MSG_WAITALL);
    if(check == 0){
        printf("Error: Project does not exist on the server.\n");
        exit(0);
    }
    else{
        int versionlen = strlen(verNo);
        send(csfd, &versionlen, sizeof(int), 0);
        send(csfd, verNo, versionlen * sizeof(char), 0);
        int check2;
        recv(csfd, &check2, sizeof(int), MSG_WAITALL);
        if(check2 == 0){
            printf("Error: Backup for version %s of project %s does not exist.\n", verNo, projName);
        }
        else{
            printf("Successfully rolled back project %s to version %s.\n", projName, verNo);
        }
    }
}

int main(int argc, char** argv){
    DIR* d = opendir("./client_folder");
    if(d == NULL)
        system("mkdir client_folder");
    closedir(d);
    if(argc != 3 && argc != 4){
        printf("Error: invalid number of arguments.\n");
        exit(0);
    }
    else if(argc == 3){
        if(strcmp(argv[1], "create") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            create(argv[2]);
        }
        else if(strcmp(argv[1], "destroy") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            destroy(argv[2]);
        }
        else if(strcmp(argv[1], "currentversion") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            currentversion(argv[2]);
        }
        else if(strcmp(argv[1], "checkout") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            printf("running checkout\n");
            checkout(argv[2]); 
        }
        else if(strcmp(argv[1], "commit") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            commit(argv[2]);
        }
        else if(strcmp(argv[1], "push") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            push(argv[2]);
        }
        else if(strcmp(argv[1], "update") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            update(argv[2]);
        }
        else if (strcmp(argv[1], "history") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            history(argv[2]);
        }
        else if(strcmp(argv[1], "upgrade") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            upgrade(argv[2]);
        }
        else{
            printf("Invalid command: %s\n", argv[1]);
            exit(0);
        }
    }
    else{
        if(strcmp(argv[1], "configure") == 0){
            configure(argv[2], argv[3], "client_folder");
        }
        else if(strcmp(argv[1], "add") == 0){
            add(argv[2], argv[3]);
        }
        else if(strcmp(argv[1], "remove") == 0){
            gitremove(argv[2], argv[3]);
        }
        else if(strcmp(argv[1], "rollback") == 0){
            getConfig("./client_folder/.configure");
            clientConnect();
            int comlen = strlen(argv[1]);
            send(csfd, &comlen, sizeof(int), 0);
            send(csfd, argv[1], strlen(argv[1]), 0);
            rollback(argv[2], argv[3]);
        }
        else{
            printf("Invalid command: %s\n", argv[1]);
            exit(0);
        }
    }
    

    freeLL(front);
    freeLL(front2);
    return 0;
}