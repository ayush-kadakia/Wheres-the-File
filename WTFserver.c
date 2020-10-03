#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>  
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>  
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <netinet/in.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <libgen.h>
#include <sys/mman.h>
#include<signal.h>

struct node{
    char* projName;
    pthread_mutex_t lock;
    struct node* next;
};

struct node* projects;
  
int port;
 
 void insertProjectNode(char* projName){
    struct node * temp = malloc(sizeof(struct node));
    temp->projName = malloc(sizeof(char) * strlen(projName) + 1);
    strcpy(temp->projName, projName);
    temp->projName[strlen(projName)] = '\0';
    pthread_mutex_init(&temp->lock, NULL);
    temp->next = NULL;
    if(projects == NULL){
        projects = temp;
        return;
    }
    else{
        struct node* ptr = projects;
        while(ptr->next != NULL){
            ptr = ptr->next;
        }
        ptr->next = temp;
    }
}

struct node* contains(char* name){
    struct node* ptr = projects;
    while(ptr != NULL){
        if(strcmp(ptr->projName, name) == 0)
            return ptr;
        ptr = ptr->next;
    }
    return NULL;
}

void freeLL(struct node* front){
    struct node* ptr = front;
    while(ptr != NULL){
        free(ptr->projName);
        pthread_mutex_destroy(&ptr->lock);
        struct node* temp = ptr;
        ptr = ptr->next;
        free(temp);
    }
}

void deleteProjectNode(char* name){
    struct node * ptr = projects;
    struct node * prev = NULL;

    if(ptr != NULL && strcmp(ptr->projName, name) == 0){
        free(ptr->projName);
        pthread_mutex_destroy(&ptr->lock);
        projects = ptr->next;
        free(ptr);
        return;
    }

    while(ptr != NULL && strcmp(ptr->projName, name) != 0){
        prev = ptr;
        ptr = ptr->next;
    }

    if(ptr == NULL)
        return;

    free(ptr->projName);
    pthread_mutex_destroy(&ptr->lock);
    prev->next = ptr->next;
    free(ptr);
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
 
void* destroy(void* arg){
    int newSocket = *((int *)arg);
    int namelen;
    recv(newSocket, &namelen, sizeof(int), MSG_WAITALL);
    char name[namelen + 1];
    recv(newSocket, name, namelen, MSG_WAITALL);
    name[namelen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d == NULL){
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Destroy failed. Project %s does not exist.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
        pthread_exit(NULL);
        //return NULL;
    }
    else{
        closedir(d);
        check = 1;
        char syscom[8 + strlen(dircheck)];
        strcpy(syscom, "rm -rf ");
        strcat(syscom, dircheck);
        syscom[7 + strlen(dircheck)] = '\0';
        system(syscom);
        send(newSocket, &check, sizeof(int), 0);
        printf("Destroy succeeded. Project %s has been destroyed.\n", name);
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    deleteProjectNode(name);
    pthread_exit(NULL);
}
 
void* checkout(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d != NULL){
        int fp;
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        int projcheck = 1;
        recv(newSocket, &projcheck, sizeof(int), MSG_WAITALL);
        if(projcheck == 0){
            printf("Checkout failed. Project %s already exists on the client.\n", name);
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
        else{
            char compname[strlen(name) + 9];
            strcpy(compname, name);
            strcat(compname, ".tar.gz ");
            compname[strlen(name)  + 8] = '\0';
            char syscom[52 + strlen(name) + strlen(compname)];
            strcpy(syscom, "cd ./server_folder && tar -cf ");
            syscom[30] = '\0';
            strcat(syscom, compname);
            syscom[30 + strlen(compname)] = '\0';
            strcat(syscom, "--exclude '.backups' ");
            strcat(syscom, name);
            syscom[51 + strlen(name) + strlen(compname)] = '\0';
            system(syscom);
            char tarpath[strlen(name) + 24];
            strcpy(tarpath, "./server_folder/");
            tarpath[16] = '\0';
            strcat(tarpath, name);
            tarpath[16 + strlen(name)] = '\0';
            strcat(tarpath, ".tar.gz");
            int fp = open(tarpath, O_RDONLY);
            int fsize;
            struct stat s;
            if(stat(tarpath, &s) == 0)
                fsize = s.st_size;
            else
                fsize = -1;
            send(newSocket, &fsize, sizeof(int), 0);
            char mani[fsize + 1];
            read(fp, mani, fsize);
            mani[fsize] = '\0';
            send(newSocket, mani, fsize, 0);
            close(fp);
            char syscom2[strlen(tarpath) + 8];
            strcpy(syscom2, "rm -rf ");
            syscom2[7] = '\0';
            strcat(syscom2, tarpath);
            system(syscom2);
            printf("Checkout succeeded. Project %s has been sent to the client.\n", name);
            close(fp);
        }
    }
    else{
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Checkout failed. Project %s does not exist on the server.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
        pthread_exit(NULL);
        return NULL;
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void* commit(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d != NULL){
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        int fcheck;
        recv(newSocket, &fcheck, sizeof(int), MSG_WAITALL);
        if(fcheck == 1){
            printf("Commit failed. Client has a .Conflict file or a non-empty .Update file.\n");
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
        char manpath[strlen(dircheck) + 11];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        manpath[strlen(dircheck) + 10] = '\0';
        int fp = open(manpath, O_RDONLY);
        int fsize;
        struct stat s;
        if(stat(manpath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        char mani[fsize + 1];
        read(fp, mani, fsize);
        mani[fsize] = '\0';
        send(newSocket, mani, strlen(mani) * sizeof(char), 0);
        close(fp);
        int sameCheck;
        recv(newSocket, &sameCheck, sizeof(int), MSG_WAITALL);
        if(sameCheck == 0){
            printf("Commit failed. Client and server project versions do not match.\n");
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
        char commitPath[strlen(dircheck) + 9];
        strcpy(commitPath, dircheck);
        commitPath[strlen(dircheck)] = '\0';
        strcat(commitPath, "/.Commit");
        commitPath[strlen(dircheck) + 8] = '\0';
 
        int fp2 = open(commitPath, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        int commSize;
        recv(newSocket, &commSize, sizeof(int), MSG_WAITALL);
        if(commSize > 0){
            char commBuffer[commSize + 1];
            recv(newSocket, commBuffer, commSize, MSG_WAITALL);
            commBuffer[commSize] = '\0';
            write(fp2, commBuffer, commSize);
        }
        close(fp2);
 
        printf("Commit succeeded.\n", name);
    }
    else{
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Commit failed. Project %s does not exist on the server.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
        pthread_exit(NULL);
        return NULL;
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void backup(char* name, char* version){
    char backupPath[strlen(name) + 25];
    strcpy(backupPath, "./server_folder/");
    strcat(backupPath, name);
    strcat(backupPath, "/.backups"); //./server_folder/testproject/.backups
    DIR* d = opendir(backupPath);
    if(d == NULL){
        char makeBackupFolder[strlen(backupPath) + 6];
        strcpy(makeBackupFolder, "mkdir ");
        strcat(makeBackupFolder, backupPath);
        system(makeBackupFolder);
    }
    closedir(d);
 
    char backupName[strlen(name) + strlen(version)];
    strcpy(backupName, name);
    strcat(backupName, version);
    char makeBackup[strlen(backupName) + strlen(name) + 57];
    strcpy(makeBackup, "cd server_folder && tar -cf ");
    strcat(makeBackup, backupName);
    strcat(makeBackup, ".tar.gz ");
    strcat(makeBackup, "--exclude '.Commit' ");
    strcat(makeBackup, name);
    system(makeBackup);
 
    char moveBackup[strlen(backupName) + strlen(name) + 40];
    strcpy(moveBackup, "cd server_folder && cp ");
    strcat(moveBackup, backupName);
    strcat(moveBackup, ".tar.gz ");
    strcat(moveBackup, name);
    strcat(moveBackup, "/.backups");
    system(moveBackup);
 
    char rmBackup[strlen(backupName) + 30];
    strcpy(rmBackup, "cd server_folder && rm ");
    strcat(rmBackup, backupName);
    strcat(rmBackup, ".tar.gz");
    system(rmBackup);
 
}
 
void* rollback(void* arg){
    int newSocket = *((int *)arg);
    int namelen;
    recv(newSocket, &namelen, sizeof(int), MSG_WAITALL);
    char name[namelen + 1];
    recv(newSocket, name, namelen, MSG_WAITALL);
    name[namelen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d == NULL){
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Rollback failed. Project %s does not exist.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
        pthread_exit(NULL);
        return NULL;
    }
    else{
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        int versionlen;
        recv(newSocket, &versionlen, sizeof(int), MSG_WAITALL);
        char version[versionlen + 1];
        recv(newSocket, version, versionlen * sizeof(char), MSG_WAITALL);
        version[versionlen] = '\0';
 
        char backupName[strlen(name) + strlen(version) + 7];
        strcpy(backupName, name);
        strcat(backupName, version);
        strcat(backupName, ".tar.gz");
 
        char backupPath[strlen(dircheck) + strlen(backupName) + 10];
        strcpy(backupPath, dircheck);
        strcat(backupPath, "/.backups/");
        strcat(backupPath, backupName);
 
        struct stat s;
        int check2;
        if(stat(backupPath, &s) == 0)
            check2 = 1;
        else
            check2 = 0;
        send(newSocket, &check2, sizeof(int), 0);
        if(check2 == 1){
            char movecmd[strlen(backupPath) + 19];
            strcpy(movecmd, "cp ");
            strcat(movecmd, backupPath);
            strcat(movecmd, " ./server_folder");
            system(movecmd);
 
            char rmcmd[strlen(name) + 27];
            strcpy(rmcmd, "cd server_folder && rm -rf ");
            strcat(rmcmd, name);
            system(rmcmd);
 
            char backupName2[strlen(name) + strlen(version) + 7];
            strcpy(backupName2, name);
            strcat(backupName2, version);
            strcat(backupName2, ".tar.gz");
 
            char untar[strlen(backupName2) + 28];
            strcpy(untar, "cd server_folder && tar -xf ");
            strcat(untar, backupName2);
            system(untar);
 
            char rmvtar[strlen(backupName2) + 23];
            strcpy(rmvtar, "cd server_folder && rm ");
            strcat(rmvtar, backupName2);
            system(rmvtar);
 
            printf("Successfully rolled back project %s to version %s.\n", name, version);
        }
        else{
            printf("Backup failed. Backup for version %s of project %s does not exist.\n", version, name);
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void* push(void* arg){
    int newSocket = *((int *)arg);
    int namelen;
    recv(newSocket, &namelen, sizeof(int), MSG_WAITALL);
    char name[namelen + 1];
    recv(newSocket, name, namelen, MSG_WAITALL);
    name[namelen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d == NULL){
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Push failed. Project %s does not exist.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
            pthread_exit(NULL);
        }
    else{
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
       
        char manpath2[strlen(name) + 26];
        strcpy(manpath2, "./server_folder/");
        strcat(manpath2, name);
        strcat(manpath2, "/.Manifest");
        int mansize2;
        struct stat mans;
        if(stat(manpath2, &mans) == 0)
            mansize2 = mans.st_size;
        char manbuffer[mansize2 + 1];
        int maniFP = open(manpath2, O_RDONLY);
        read(maniFP, manbuffer, mansize2);
        manbuffer[mansize2] = '\0';
        int m = 0;
        close(maniFP);
        while(m < mansize2){
            if(manbuffer[m] == '\n'){
                break;
            }
            m++;
        }
        char version[m + 1];
        int counter;
        for(counter = 0; counter < (m); counter++){
            version[counter] = manbuffer[counter];
        }
        version[m] = '\0';
        backup(name, version);
 
        char commitPath[strlen(dircheck) + 9];
        strcpy(commitPath, dircheck);
        commitPath[strlen(dircheck)] = '\0';
        strcat(commitPath, "/.Commit");
        commitPath[strlen(dircheck) + 8] = '\0';
        int fsize;
        struct stat s;
        if(stat(commitPath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        if(fsize == -1){
            printf("Push failed. .Commit file for project %s does not exist on the server.\n", name);
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
        int chashlen;
        recv(newSocket, &chashlen, sizeof(int), MSG_WAITALL);
 
        char chbuffer[chashlen + 1];
        recv(newSocket, chbuffer, chashlen * sizeof(char), MSG_WAITALL);
        chbuffer[chashlen] = '\0';
 
        //insert code to generate server-side hash here
        unsigned char* result =  md5_for_file(commitPath);
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
 
        int samecheck = 0;
        if(strcmp(chbuffer, hex) == 0)
            samecheck = 1;
        send(newSocket, &samecheck, sizeof(int), 0);
        if(samecheck == 0){
            printf("Push failed. .Commit file on server is not the same as .Commit file on client, or .Commit file on server has been overwritten by a different client.\n");
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
 
        int histSize;
        char historyPath[strlen(dircheck) + 10];
        strcpy(historyPath, dircheck);
        strcat(historyPath, "/.History");
        historyPath[strlen(dircheck) + 9] = '\0';
        int fp4 = open(historyPath, O_WRONLY | O_APPEND | O_CREAT, 00600);
        recv(newSocket, &histSize, sizeof(int), MSG_WAITALL);
        if(histSize > 0){
            char cHist[histSize + 1];
            recv(newSocket, cHist, histSize * sizeof(char), MSG_WAITALL);
            cHist[histSize] = '\0';
            write(fp4, cHist, strlen(cHist) * sizeof(char));
        }
        close(fp4);
        int hasNewFiles;
        recv(newSocket, &hasNewFiles, sizeof(int), MSG_WAITALL);
        if(hasNewFiles == 1){
            char tarpath[strlen(name) + 23];
            strcpy(tarpath, "./server_folder/");
            strcat(tarpath, name);
            strcat(tarpath, ".tar.gz");
            int fp2 = open(tarpath, O_WRONLY | O_APPEND | O_CREAT, 00600);
            int tarsize;
            recv(newSocket, &tarsize, sizeof(int), MSG_WAITALL);
            char tarfile[tarsize + 1];
            recv(newSocket, tarfile, tarsize * sizeof(char), MSG_WAITALL);
            tarfile[tarsize] = '\0';
            write(fp2, tarfile, tarsize * sizeof(char));
 
            char cmd[strlen(name) + 36];
            memset(cmd, '\0', strlen(cmd));
            strcpy(cmd, "cd server_folder && tar -xf ");
            strcat(cmd, name);
            strcat(cmd, ".tar.gz");
            system(cmd);
            close(fp2);
            //remove the .tar from server
            char rmvcmd[strlen(name) + 35];
            memset(rmvcmd, '\0', strlen(rmvcmd));
            strcpy(rmvcmd, "cd server_folder && rm -rf ");
            strcat(rmvcmd, name);
            strcat(rmvcmd, ".tar.gz");
            system(rmvcmd);  
        }
 
 
 
        //code to receive all added/modified files
        //for each a/m file, rm each file (if m) and write new file using received buffer
        //for each removed file, rm file
 
        int fp = open(commitPath, O_RDONLY);
        char scbuffer[fsize + 1];
        read(fp, scbuffer, fsize);
        scbuffer[fsize] = '\0';
        int toCheck = 1;
        int n = 0;
        int j = 0;
        while(n < fsize){
            if(toCheck == 1){
                if(scbuffer[n] == 'R'){
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
                    strcpy(syscom, "rm -rf ./server_folder/");
                    strcat(syscom, toRemove);
                    system(syscom);
                }
               
                toCheck = 0;
            }
            else if(scbuffer[n] == '\n')
                toCheck = 1;
            n++;
        }
        close(fp);
 
        char manpath[strlen(dircheck) + 10];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        char syscom2[strlen(manpath) + 7];
        strcpy(syscom2, "rm -rf ");
        strcat(syscom2, manpath);
        system(syscom2);
 
        int mansize = 0;
        char* dump;
        recv(newSocket, &mansize, sizeof(int), MSG_WAITALL);
        if(mansize > 0){
            char helper[mansize + 1];
            recv(newSocket, helper, mansize * sizeof(char), MSG_WAITALL);
            helper[mansize] = '\0';
            int fp3 = open(manpath, O_WRONLY | O_APPEND | O_CREAT, 00600);
            write(fp3, helper, strlen(helper));
            close(fp3);
        }
 
        char rmvcmd2[strlen(commitPath) + 3];
        strcpy(rmvcmd2, "rm ");
        strcat(rmvcmd2, commitPath);
        system(rmvcmd2);
        printf("Push succeeded. Project %s has been updated.\n", name);
 
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void* currentversion(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d != NULL){
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        char manpath[strlen(dircheck) + 11];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        manpath[strlen(dircheck) + 10] = '\0';
        int fp = open(manpath, O_RDONLY);
        int fsize;
        struct stat s;
        if(stat(manpath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        char mani[fsize + 1];
        read(fp, mani, fsize);
        mani[fsize] = '\0';
        send(newSocket, mani, strlen(mani) * sizeof(char), 0);
        close(fp);
        printf("currentversion succeeded. Current version of project %s has been sent to the client.\n", name);
    }
    else{
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("currentversion failed. Project %s does not exist on the server.\n", name);
    }
}
 
void* create(void* arg){
    int newSocket = *((int *)arg);
    int namelen;
    recv(newSocket, &namelen, sizeof(int), MSG_WAITALL);
    char name[namelen + 1];
    recv(newSocket, name, namelen, MSG_WAITALL);
    name[namelen] = '\0';
    insertProjectNode(name);
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d == NULL){
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        char syscom[7 + strlen(dircheck)];
        strcpy(syscom, "mkdir ");
        strcat(syscom, dircheck);
        syscom[6 + strlen(dircheck)] = '\0';
        system(syscom);
        char manpath[strlen(dircheck) + 11];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        manpath[strlen(dircheck) + 10] = '\0';
        int fp = open(manpath, O_WRONLY | O_APPEND | O_CREAT, 00600);
        write(fp, "1\n", strlen("1\n"));
        close(fp);
        int fsize;
        struct stat s;
        if(stat(manpath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        int fp2 = open(manpath, O_RDONLY);
        char mani[fsize + 1];
        read(fp2, mani, fsize);
        mani[fsize] = '\0';
        send(newSocket, mani, strlen(mani) * sizeof(char), 0);
        close(fp2);
        printf("Create succeeded. Project %s has been created.\n", name);
    }
    else{
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        printf("Create failed. Project %s already exists.\n", name);
        if(hasLocked == 1){
            pthread_mutex_unlock(&temp->lock);
        }
        pthread_exit(NULL);
        return NULL;
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void* update(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d != NULL){
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        char manpath[strlen(dircheck) + 11];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        manpath[strlen(dircheck) + 10] = '\0';
        int fp = open(manpath, O_RDONLY);
        int fsize;
        struct stat s;
        if(stat(manpath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        char mani[fsize + 1];
        read(fp, mani, fsize);
        mani[fsize] = '\0';
        send(newSocket, mani, strlen(mani) * sizeof(char), 0);
        close(fp);
 
        printf("Update succeeded.\n", name);
    }
    else{
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Update failed. Project %s does not exist on the server.\n", name);
    }
}
 
void* upgrade(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    struct node* temp = contains(name);
    int hasLocked = 0;
    if(temp != NULL){
        pthread_mutex_lock(&temp->lock);
        hasLocked = 1;
    }
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d != NULL){
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        int clientCheck;
        recv(newSocket, &clientCheck, sizeof(int), MSG_WAITALL);
        if(clientCheck == 1){
            printf("Upgrade failed. Client does not have a .Update file or does have a .Conflict file.\n");
            if(hasLocked == 1){
                pthread_mutex_unlock(&temp->lock);
            }
            pthread_exit(NULL);
            return NULL;
        }
        char manpath[strlen(dircheck) + 11];
        strcpy(manpath, dircheck);
        strcat(manpath, "/.Manifest");
        manpath[strlen(dircheck) + 10] = '\0';
        int fp = open(manpath, O_RDONLY);
        int fsize;
        struct stat s;
        if(stat(manpath, &s) == 0)
            fsize = s.st_size;
        else
            fsize = -1;
        send(newSocket, &fsize, sizeof(int), 0);
        char mani[fsize + 1];
        read(fp, mani, fsize);
        mani[fsize] = '\0';
        send(newSocket, mani, fsize * sizeof(char), 0);
        close(fp);
        int hasNewFiles = 0;
        recv(newSocket, &hasNewFiles, sizeof(int), MSG_WAITALL);
        if(hasNewFiles == 1){
            //tar all files that need to be sent to client
            int commandSize;
            recv(newSocket, &commandSize, sizeof(int), MSG_WAITALL);
            char command[commandSize + 1];
            recv(newSocket, command, commandSize * sizeof(char), MSG_WAITALL);
            command[commandSize] = '\0';
            system(command);
            //store the .tar in a buffer and send it over to client
            char tarpath[strlen(name) + 24];
            memset(tarpath, '\0', strlen(tarpath));
            strcat(tarpath, "./server_folder/");
            strcat(tarpath, name);
            strcat(tarpath, ".tar.gz");
 
            int fp2 = open(tarpath, O_RDONLY);
            int tarsize;
            struct stat s;
            if(stat(tarpath, &s) == 0)
                tarsize = s.st_size;
            else
                tarsize = -1;
            send(newSocket, &tarsize, sizeof(int), 0);
            char buffer[tarsize + 1];
            read(fp2, buffer, tarsize);
            buffer[tarsize] = '\0';
            send(newSocket, buffer, tarsize * sizeof(char), 0);
 
            //remove the .tar from server
            char rmvcmd[strlen(name) + 35];
            memset(rmvcmd, '\0', strlen(rmvcmd));
            strcpy(rmvcmd, "cd server_folder && rm -rf ");
            strcat(rmvcmd, name);
            strcat(rmvcmd, ".tar.gz");
            system(rmvcmd);
            close(fp2);
        }
    }
    else{
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("Upgrade failed. Project %s does not exist on the server.\n", name);
    }
    if(hasLocked == 1){
        pthread_mutex_unlock(&temp->lock);
    }
    pthread_exit(NULL);
}
 
void* history(void* arg){
    int newSocket = *((int *)arg);
    int plen;
    recv(newSocket, &plen, sizeof(int), MSG_WAITALL);
    char name[plen + 1];
    recv(newSocket, name, plen, MSG_WAITALL);
    name[plen] = '\0';
    char dircheck[17 + strlen(name)];
    strcpy(dircheck, "./server_folder/");
    strcat(dircheck, name);
    dircheck[16 + strlen(name)] = '\0';
    DIR* d = opendir(dircheck);
    int check;
    if(d == NULL){
        closedir(d);
        check = 0;
        send(newSocket, &check, sizeof(int), 0);
        printf("History failed. Project %s does not exist.\n", name);
    }
    else{
        closedir(d);
        check = 1;
        send(newSocket, &check, sizeof(int), 0);
        char historyPath[strlen(dircheck) + 9];
        strcpy(historyPath, dircheck);
        strcat(historyPath, "/.History");
        int fp = open(historyPath, O_RDONLY);
        struct stat s;
        int fileSize;
        if(stat(historyPath, &s) == 0)
            fileSize = s.st_size;
        else{
            fileSize = -1;
        }
        send(newSocket, &fileSize, sizeof(fileSize), 0);
        char buffer[fileSize + 1];
        read(fp, buffer, fileSize);
        buffer[fileSize] = '\0';
        send(newSocket, buffer, strlen(buffer), 0);
        close(fp);
    }
}

void onCtrlC(int n){
    write(1, "\nEnding WTFserver.\n", strlen("\nEnding WTFserver.\n"));
    exit(0);
}
 
int main(int argc, char** argv){
    DIR* d = opendir("./server_folder");
    if(d == NULL)
        system("mkdir server_folder");
    closedir(d);
    if(argc == 2){
        if(atoi(argv[1]) != 0)
            port = atoi(argv[1]);
        else{
            printf("Error: invalid port number provided.\n");
            return(0);
        }
    }
    else{
        printf("Error: invalid number of arguments");
        return(0);
    }
    int ssfd = socket(AF_INET, SOCK_STREAM, 0);
    int csfd;
    struct sockaddr_in addr;
    int length = sizeof(addr);
    struct sockaddr_storage serverStorage;
        socklen_t addr_size;
    if(ssfd < 0){
        printf("Error occurred when creating server socket.\n");
        exit(0);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    int bcheck = bind(ssfd, (struct sockaddr*)&addr, sizeof(addr));
    if (bcheck  < 0)
    {
        printf("bind failed\n");
        exit(0);
    }
    if (listen(ssfd, 3) < 0)
    {
        printf("listen failed\n");
        exit(0);
    }

    signal(SIGINT, onCtrlC);
    
    pthread_t tid[60];
    int i = 0;
    while(1)
    {
        addr_size = sizeof serverStorage;
        csfd = accept(ssfd, (struct sockaddr*) &serverStorage, &addr_size);
        if(csfd != -1)
            printf("A client has connected successfully.\n");
        int comlen;
        recv(csfd, &comlen, sizeof(int), MSG_WAITALL);
        char com[comlen + 1];
        recv(csfd, com, comlen * sizeof(char), MSG_WAITALL);
        com[comlen] = '\0';
        if(strcmp(com, "create") == 0){
            if(pthread_create(&tid[i], NULL, create, &csfd) != 0 )
                printf("Failed to create thread for create\n");
        }
        else if(strcmp(com, "destroy") == 0){
            if(pthread_create(&tid[i], NULL, destroy, &csfd) != 0 )
                printf("Failed to create thread for destroy\n");
        }
        else if(strcmp(com, "currentversion") == 0){
            if(pthread_create(&tid[i], NULL, currentversion, &csfd) != 0 )
                printf("Failed to create thread for currentversion\n");
        }
        else if(strcmp(com, "checkout") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, checkout, &csfd) != 0 )
                printf("Failed to create thread for checkout\n");
        }
        else if(strcmp(com, "commit") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, commit, &csfd) != 0 )
                printf("Failed to create thread for commit\n");
        }
        else if(strcmp(com, "push") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, push, &csfd) != 0 )
                printf("Failed to create thread for push\n");
        }
        else if(strcmp(com, "update") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, update, &csfd) != 0 )
                printf("Failed to create thread for update\n");
        }
        else if(strcmp(com, "history") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, history, &csfd) != 0 )
                printf("Failed to create thread for history\n");
        }
        else if(strcmp(com, "upgrade") == 0){
            printf("received command: %s\n", com);
            if(pthread_create(&tid[i], NULL, upgrade, &csfd) != 0 )
                printf("Failed to create thread for upgrade\n");
        }
        else if(strcmp(com, "rollback") == 0){
            if(pthread_create(&tid[i], NULL, rollback, &csfd) != 0 )
                printf("Failed to create thread for rollback\n");            
        }                    
        else{
            printf("Error: invalid command received.\n");
        }    
       
        if( i >= 60)
        {
          i = 0;
          while(i < 60)
          {
            pthread_join(tid[i++],NULL);
          }
          i = 0;
        }
    }
    freeLL(projects);
    return 0;
}