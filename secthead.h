#include <stdio.h>
#include <stdint.h>

char* getType(uint32_t sh_type){
    switch(sh_type){
        case 0:
            return "NULL";
            break;
        case 1:
            return "PROGBITS";
            break;
        case 2:
            return "SYMTAB";
            break;
        case 3:
            return "STRTAB";
            break;
        case 4:
            return "RELA";
            break;    
        case 5:
            return "HASH";
            break;
        case 6:
            return "DYNAMIC";
            break;
        case 7:
            return "NOTE";
            break;
        case 8:
            return "NOBITS";
            break;
        case 9:
            return "REL";
            break;
        case 10:
            return "SHLIB";
            break;
        case 11:
            return "DYNSYM";
            break;
        default:
            return "NONE";
            break;
    }
}

char *getFlag(uint64_t sh_flag){
    switch(sh_flag){
        case 0x1:
            return "W";
            break;
        case 0x2:
            return "A";
            break;
        case 0x3:
            return "WA";
            break;
        case 0x4 :
            return "X";
            break;
        case 0x6:
            return "AX";
            break;
        case 0x10:
            return "M";
            break;
        case 0x20:
            return "STR";
            break; 
        case 0x30:
            return "MS";
            break;   
        case 0x40:
            return "IL";
            break;
        case 0x42:
            return "AI";
            break;
        case 0x80:
            return "LO";
            break;
        case 0x100:
            return "OSNC";
            break;
        case 0x200:
            return "G";
            break;
        case 0x400:
            return "TLS";
            break;
        case 0x0ff00000:
            return "MOS";
            break;
        case 0x10000000:
            return "A64L";
            break;
        case 0x40000000:
            return "O";
            break;
        case 0x80000000:
            return "EX";
            break;
        case 0xf0000000:
            return "MP";
            break;
        default:
            return " ";
            break;
    }
}