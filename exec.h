#include <stdio.h>
#include <stdint.h>
typedef struct e_64h{
    uint8_t     e_ident[16];         /* Magic number and other info */
    uint16_t    e_type;              /* Object file type */
    uint16_t    e_machine;           /* Architecture */
    uint32_t    e_version;           /* Object file version */
    uint64_t    e_entry;             /* Entry point virtual address */
    uint64_t    e_phoff;             /* Program header table file offset */
    uint64_t    e_shoff;             /* Section header table file offset */
    uint32_t    e_flags;             /* Processor-specific flags */
    uint16_t    e_ehsize;            /* ELF header size in bytes */
    uint16_t    e_phentsize;         /* Program header table entry size */
    uint16_t    e_phnum;             /* Program header table entry count */
    uint16_t    e_shentsize;         /* Section header table entry size */
    uint16_t    e_shnum;             /* Section header table entry count */
    uint16_t    e_shstrndx;          /* Section header string table index */
}e_64h;
typedef struct e_64Shdr{
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    uint64_t   sh_addr;
    uint64_t   sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} e_64Shdr;