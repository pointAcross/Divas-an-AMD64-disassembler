//#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>
#include "exec.h"
char* section_header(struct e_64h head,FILE* file){
    struct e_64Shdr shdr;
    int shoff = head.e_shoff;
    int shentsize = head.e_shentsize;
    char* shname = NULL;
    fseek(file, shoff + head.e_shstrndx * head.e_shentsize, SEEK_SET);
    fread(&shdr, 1, sizeof (shdr), file);  
    shname = malloc(shdr.sh_size);//allocate the size of the string table section
    fseek(file,shdr.sh_offset,SEEK_SET);//go to the start of the section, using it's offset
    fread(shname,1,shdr.sh_size,file);//read around sh_size bytes of data.
    return shname;
}
e_64Shdr get_section_by_name(char* text,FILE* file, struct e_64h head){
    struct e_64Shdr shdr;
    char* shname;int iter;
    shname = section_header(head,file);
    for(iter = 0; iter<head.e_shnum;iter++){
        const char* name = "";
        fseek(file, head.e_shoff + iter * head.e_shentsize, SEEK_SET);
        fread(&shdr,1,sizeof(shdr),file);
        if(shdr.sh_name){
            name = shname +shdr.sh_name;
            if(strcmp(name,text)== 0){
                printf("%s\n",name);
                return shdr;
                break;
                }
            }
        }
    }
int main(){
    struct e_64h head;
    struct e_64Shdr shdr;
    uint64_t* bytes;
    FILE* fp;
    int i,ssize;
    uint64_t offset;
    if(fp = fopen("def","r")){
        fread(&head,1,sizeof(head),fp);
        //verifies the magic number (E_IDENT)
        if(head.e_ident[0]==0x7f && head.e_ident[1]=='E' && head.e_ident[2]=='L' &&head.e_ident[3]=='F'){
            printf("\n[+] Elf Verified\n");
            shdr = get_section_by_name(".text",fp,head);
            offset = shdr.sh_offset;
            fseeko(fp,offset,SEEK_SET);
            ssize = shdr.sh_size;
            uint64_t disect[ssize];
            bytes = malloc(ssize);
            //read bytes of the text section
            for(i = 0;i<shdr.sh_size;i++){
                fread(bytes,1,1,fp);
                offset++;
                fseeko(fp,offset,SEEK_SET);
                disect[i] = *bytes;
                printf("%x ",disect[i]);
            }
            printf("\n");
        }
        else{
            perror("\n[-] Bad ELF/ Not an ELF based file\n");
        }
    }
}

