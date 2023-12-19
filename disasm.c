#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>
#include "exec.h"
#include "secthead.h"

char *section_header(struct e_64h head, FILE *file){
    struct e_64Shdr shdr;
    int shoff = head.e_shoff;
    int shentsize = head.e_shentsize;
    char *shname = NULL;
    fseek(file, shoff + head.e_shstrndx * head.e_shentsize, SEEK_SET);
    fread(&shdr, 1, sizeof(shdr), file);
    shname = malloc(shdr.sh_size);         // allocate the size of the string table section
    fseek(file, shdr.sh_offset, SEEK_SET); // go to the start of the section, using it's offset
    fread(shname, 1, shdr.sh_size, file);  // read around sh_size bytes of data.
    return shname;
}
e_64Shdr get_section_by_name(char *text, FILE *file, struct e_64h head){
    struct e_64Shdr shdr;
    char *shname;
    int iter;
    shname = section_header(head, file);
    if( (strcmp(text,"0")) == 0){
        printf("S.No  Name \t\t  Type \t\t     Address  Offset   Size\tEntsz Flags Lnk Inf Addraln\n");
    }
    for (iter = 0; iter < head.e_shnum; iter++){
        const char *name = "";
        fseek(file, head.e_shoff + iter * head.e_shentsize, SEEK_SET);
        fread(&shdr, 1, sizeof(shdr), file);
        if (shdr.sh_name){
            name = shname + shdr.sh_name;
            if( (strcmp(text,"0")) == 0){
                char *type;
                type = getType(shdr.sh_type);
                char *flag;
                flag = getFlag(shdr.sh_flags);
                printf("[%02d] %-20s %-8s %16x   %06x   %06x   %x   \t%-04s %02x  %x  %x\n",iter,name,type,shdr.sh_addr,shdr.sh_offset,shdr.sh_size,shdr.sh_entsize,flag,shdr.sh_link,shdr.sh_info,shdr.sh_addralign);
            }
            else{
                if (strcmp(name, text) == 0)
                {
                    printf("%s\n", name);
                    return shdr;
                    break;
                }
            }
        }
    }
}
int main()
{
    struct e_64h head;
    struct e_64Shdr shdr;
    int i;
    uint8_t *bytes;
    FILE *fp;
    csh handle;
    cs_insn *insn;
    size_t count;
    if (fp = fopen("def", "r"))
    {
        fread(&head, 1, sizeof(head), fp);
        // verifies the magic number (E_IDENT)
        if (head.e_ident[0] == 0x7f && head.e_ident[1] == 'E' && head.e_ident[2] == 'L' && head.e_ident[3] == 'F')
        {
            printf("\n[+] Elf Verified\n");
            shdr = get_section_by_name(".text", fp, head);
            bytes = malloc(shdr.sh_size);
            fseeko(fp, shdr.sh_offset, SEEK_SET);
            fread(bytes,1,shdr.sh_size,fp);// read bytes of the text section
            get_section_by_name("0",fp,head);
            for(i = 0;i<shdr.sh_size;i++){
                printf("%02x ",bytes[i]);
            }
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
                printf("Error printing disassembly, please check capstone docs\n");
            }
            else
            {
                count = cs_disasm(handle, bytes, sizeof(bytes) - 1, shdr.sh_addr,0,&insn);//RETURNS ERROR
                if(count>0){
                    size_t j;
                    printf("\nDisassembly\n");
                    for(j = 0; j<count;j++){
                        printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);//absolutely gutting
                    }
                    cs_free(insn,count);
                }
                else{
                    printf("A failer occured in disassemble");
                }
            }
        }
        else
        {
            perror("\n[-] Bad ELF/ Not an ELF based file\n");
        }
    }
}