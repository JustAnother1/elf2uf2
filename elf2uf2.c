/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "elf.h"  // documentation: "man 5 elf"

#define VERSION_STRING "0.0.1"

typedef struct {
    uint32_t id;
    const char* name;
} family;

typedef struct _node {
    uint32_t elf_start_offset;
    uint32_t target_start_addr;
    uint32_t target_size;
    struct _node* next;
} mem_area;


struct UF2_Block {
    // 32 byte header
    uint32_t magicStart0;
    uint32_t magicStart1;
    uint32_t flags;
    uint32_t targetAddr;
    uint32_t payloadSize;
    uint32_t blockNo;
    uint32_t numBlocks;
    uint32_t fileSize; // or familyID;
    uint8_t data[476];
    uint32_t magicEnd;
} UF2_Block;

static family allFamilies[] = {
        {0x00ff6919, "ST STM32L4xx"},
        {0x04240bdf, "ST STM32L5xx"},
        {0x06d1097b, "ST STM32F411xC"},
        {0x11de784a, "M0SENSE BL702"},
        {0x16573617, "Microchip (Atmel) ATmega32"},
        {0x1851780a, "Microchip (Atmel) SAML21"},
        {0x1b57745f, "Nordic NRF52"},
        {0x1c5f21b0, "ESP32"},
        {0x1e1f432d, "ST STM32L1xx"},
        {0x202e3a91, "ST STM32L0xx"},
        {0x21460ff0, "ST STM32WLxx"},
        {0x22e0d6fc, "Realtek AmebaZ RTL8710B"},
        {0x2abc77ec, "NXP LPC55xx"},
        {0x2b88d29c, "ESP32-C2"},
        {0x2dc309c5, "ST STM32F411xE"},
        {0x300f5633, "ST STM32G0xx"},
        {0x31d228c6, "GD32F350"},
        {0x332726f6, "ESP32-H2"},
        {0x3379CFE2, "Realtek AmebaD RTL8720D"},
        {0x3d308e94, "ESP32-P4"},
        {0x4b684d71, "Sipeed MaixPlay-U4(BL618)"},
        {0x4c71240a, "ST STM32G4xx"},
        {0x4f6ace52, "LISTENAI CSK300x/400x"},
        {0x4fb2d5bd, "NXP i.MX RT10XX"},
        {0x51e903a8, "Xradiotech 809"},
        {0x53b80f00, "ST STM32F7xx"},
        {0x540ddf62, "ESP32-C6"},
        {0x55114460, "Microchip (Atmel) SAMD51"},
        {0x57755a57, "ST STM32F4xx"},
        {0x5a18069b, "Cypress FX2"},
        {0x5d1a0a2e, "ST STM32F2xx"},
        {0x5ee21072, "ST STM32F103"},
        {0x621e937a, "Nordic NRF52833"},
        {0x647824b6, "ST STM32F0xx"},
        {0x675a40b0, "Beken 7231U/7231T"},
        {0x68ed2b88, "Microchip (Atmel) SAMD21"},
        {0x699b62ec, "WCH CH32V2xx and CH32V3xx"},
        {0x6a82cc42, "Beken 7251/7252"},
        {0x6b846188, "ST STM32F3xx"},
        {0x6d0922fa, "ST STM32F407"},
        {0x6db66082, "ST STM32H7xx"},
        {0x6e7348a8, "LISTENAI CSK60xx"},
        {0x6f752678, "Nordic NRF52832xxAB"},
        {0x70d16653, "ST STM32WBxx"},
        {0x72721d4e, "Nordic NRF52832xxAA"},
        {0x77d850c4, "ESP32-C61"},
        {0x7b3ef230, "Beken 7231N"},
        {0x7be8976d, "Renesas RA4M1"},
        {0x7eab61ed, "ESP8266"},
        {0x7f83e793, "NXP KL32L2x"},
        {0x8fb060fe, "ST STM32F407VG"},
        {0x9517422f, "Renesas RZ/A1LU (R7S7210xx)"},
        {0x9af03e33, "GigaDevice GD32VF103"},
        {0x9fffd543, "Realtek Ameba1 RTL8710A"},
        {0xa0c97b8e, "ArteryTek AT32F415"},
        {0xada52840, "Nordic NRF52840"},
        {0xbfdd4eee, "ESP32-S2"},
        {0xc47e5767, "ESP32-S3"},
        {0xd42ba06c, "ESP32-C3"},
        {0xde1270b7, "Boufallo 602"},
        {0xe08f7564, "Realtek AmebaZ2 RTL8720C"},
        {0xe48bff56, "Raspberry Pi RP2040"},
        {0xe48bff57, "Raspberry Pi Microcontrollers: Absolute (unpartitioned) download"},
        {0xe48bff58, "Raspberry Pi Microcontrollers: Data partition download"},
        {0xe48bff59, "Raspberry Pi RP2350, Secure Arm image"},
        {0xe48bff5a, "Raspberry Pi RP2350, RISC-V image"},
        {0xe48bff5b, "Raspberry Pi RP2350, Non-secure Arm image"},
        {0xf71c0343, "ESP32-C5"},
};

static bool verbose = false;
static uint64_t fam_id = 0;
static unsigned long int payload_size = 256;
static char* elf_name = NULL;
static char* uf2_name = NULL;
static uint32_t program_table_offset = 0;
static int number_program_table_entries = 0;
static mem_area* memories = NULL;
static uint32_t complete_memory_size = 0;


static void print_usage(void);
static void print_all_families(void);
static void report_family(void);
static int read_elf_file_header(FILE* elf_file);
static int copy_data(FILE* elf_file);
static int read_program_table(FILE* elf_file);
static int add_memory(uint32_t elf_start_offset, uint32_t target_start_addr, uint32_t target_size);


static int read_elf_file_header(FILE* elf_file)
{
    Elf32_Ehdr ehdr;
    if(1 != fread(&ehdr, sizeof(ehdr), 1, elf_file))
    {
        fprintf(stderr, "could not read the elf file header from %s !\n", elf_name);
        return 8;
    }

    // magic numbers in header
    if(    (ELFMAG0 != ehdr.e_ident[EI_MAG0])
        || (ELFMAG1 != ehdr.e_ident[EI_MAG1])
        || (ELFMAG2 != ehdr.e_ident[EI_MAG2])
        || (ELFMAG3 != ehdr.e_ident[EI_MAG3]) )
    {
        fprintf(stderr, "%s is not an elf file !\n", elf_name);
        return 9;
    }
    if(ELFCLASS32 != ehdr.e_ident[EI_CLASS])
    {
        fprintf(stderr, "ERROR: %s is not an 32 bit elf file !\n", elf_name);
        return 10;
    }
    if(true == verbose)
    {
        printf("Entry point at 0x%08x !\n", ehdr.e_entry);
        // program header
        if(0 == ehdr.e_phoff)
        {
            printf("No Program header table !\n");
        }
        else
        {
            printf("Program header table at offset %d !\n", ehdr.e_phoff);
            printf("program header entries are %d bytes long\n", ehdr.e_phentsize);
            printf("program header table has %d entries\n", ehdr.e_phnum);
        }
        // section header
        if(0 == ehdr.e_shoff)
        {
            printf("No section header table !\n");
        }
        else
        {
            printf("section header table at offset %d !\n", ehdr.e_shoff);
            printf("section header entries are %d bytes long\n", ehdr.e_shentsize);
            printf("section header table has %d entries\n", ehdr.e_shnum);
        }
    }
    if(0 == ehdr.e_phoff)
    {
        fprintf(stderr, "ERROR: %s does not contain a program header table !\n", elf_name);
        return 11;
    }
    if(ehdr.e_phentsize != sizeof(Elf32_Phdr))
    {
        fprintf(stderr, "ERROR: %s reports wrong program header table entry size !\n", elf_name);
        return 12;
    }
    if(1 > ehdr.e_phnum)
    {
        fprintf(stderr, "ERROR: %s contains an empty program header table !\n", elf_name);
        return 13;
    }
    if(PN_XNUM < ehdr.e_phnum)
    {
        fprintf(stderr, "ERROR: %s contains an program header table with an invalid number of entries!\n", elf_name);
        return 15;
    }
    program_table_offset = ehdr.e_phoff;
    number_program_table_entries = ehdr.e_phnum;
    return 0;
}

static void report_family(void)
{
    int i;
    int num_families = sizeof(allFamilies)/ sizeof(family);
    for(i = 0; i < num_families; i++)
    {
        if(allFamilies[i].id == fam_id)
        {
            printf("creating UF2 file for %s\n", allFamilies[i].name);
            return;
        }
    }
    printf("creating UF2 file for the unknown family id 0x%08llx\n", fam_id);
}

static void print_all_families(void)
{
    int i;
    int num_families = sizeof(allFamilies)/ sizeof(family);
    printf(" id        : name\n");
    for(i = 0; i < num_families; i++)
    {
        printf("0x%08x : %s\n", allFamilies[i].id, allFamilies[i].name);
    }
}

static int add_memory(uint32_t elf_start_offset, uint32_t target_start_addr, uint32_t target_size)
{
    mem_area*  entry = NULL;
    entry = malloc(sizeof(mem_area));
    if(NULL == entry)
    {
        fprintf(stderr, "ERROR: malloc() failed! no free RAM ?\n");
        return 21;
    }
    entry->elf_start_offset = elf_start_offset;
    entry->target_start_addr = target_start_addr;
    entry->target_size = target_size;
    entry->next = NULL;

    if(NULL == memories)
    {
        // first entry
        memories = entry;
    }
    else
    {
        mem_area* last = memories;
        while(last->next != NULL)
        {
            last = last->next;
        }
        // add the new area
        last->next = entry;
    }
    return 0;
}

static int read_program_table(FILE* elf_file)
{
    unsigned int prog_entry;
    Elf32_Phdr program_table;

    for(prog_entry = 0; prog_entry < number_program_table_entries; prog_entry++)
    {
        if(1 != fread(&program_table, sizeof(Elf32_Phdr), 1, elf_file))
        {
            fprintf(stderr, "ERROR: could not read the program table from %s !\n", elf_name);
            return 8;
        }

        // check Program Table Entry
        if(PT_LOAD == program_table.p_type)
        {

            uint32_t elf_start_offset = program_table.p_offset;
            uint32_t target_start_addr;
            uint32_t target_size;
            int i;

            if(0 ==  program_table.p_paddr)
            {
                // physical address is 0
                // -> use virtual address
                target_start_addr = program_table.p_vaddr;
            }
            else
            {
                // physical address is valid
                // -> use it
                target_start_addr = program_table.p_paddr;
            }

            if((0 == program_table.p_memsz) || (0 == program_table.p_filesz))
            {
                // No data for that section
                continue;
            }
            // else OK
            target_size = program_table.p_filesz;
            complete_memory_size = complete_memory_size + target_size;
            i = add_memory(elf_start_offset, target_start_addr, target_size);
            if(0 != i)
            {
                // something went wrong
                return i;
            }
        }
        // else not a load able segment -> skip
    }
    return 0;
}

static int copy_data(FILE* elf_file)
{
    FILE* uf2_file;
    uint8_t buffer[476];
    uint32_t num;
    mem_area* cur_mem = memories;

    // prepare UF2 block

    num = complete_memory_size / payload_size;
    if(num * payload_size < complete_memory_size)
    {
        num++;
    }

    UF2_Block.magicStart0 = 0x0A324655;
    UF2_Block.magicStart1 = 0x9E5D5157;
    UF2_Block.magicEnd = 0x0AB16F30;
    UF2_Block.flags = 0x00002000;
    UF2_Block.fileSize = (uint32_t)(fam_id & 0xffffffff);
    UF2_Block.blockNo = 0;
    UF2_Block.numBlocks = num;

    // create UF2 file
    uf2_file = fopen(uf2_name, "wb");
    if(NULL == uf2_file)
    {
        fprintf(stderr, "ERROR: can not write the file  %s\n", uf2_name);
        return 14;
    }

    while(NULL != cur_mem)
    {
        if(0 != fseek(elf_file, cur_mem->elf_start_offset, SEEK_SET))
        {
            fprintf(stderr, "ERROR: can not read data from the file  %s\n", elf_name);
            fclose(uf2_file);
            return 17;
        }
        while(cur_mem->target_size > 0)
        {
            int copy_size = payload_size;

            UF2_Block.targetAddr = cur_mem->target_start_addr;
            if(cur_mem->target_size < payload_size)
            {
                // last block
                copy_size = cur_mem->target_size;
            }
            // read from elf
            if(1 != fread(&buffer, copy_size, 1, elf_file))
            {
                fprintf(stderr, "ERROR: could not read data from %s !\n", elf_name);
                fclose(uf2_file);
                return 18;
            }
            // write a UF2 Block
            memset(UF2_Block.data, 0, 476);
            memcpy(UF2_Block.data, buffer, copy_size);
            UF2_Block.payloadSize = copy_size;
            cur_mem->target_size = cur_mem->target_size - copy_size;
            cur_mem->target_start_addr = cur_mem->target_start_addr + copy_size;
            if(copy_size < payload_size)
            {
                // last block not completely filled
                // -> check if next memory area is directly attached
                if(NULL != cur_mem->next)
                {
                    uint32_t end_address = UF2_Block.targetAddr + copy_size;
                    cur_mem = cur_mem->next;
                    if(end_address == cur_mem->target_start_addr)
                    {
                        int bytes_to_fill = payload_size - copy_size;
                        // this is a continuation
                        if(0 != fseek(elf_file, cur_mem->elf_start_offset, SEEK_SET))
                        {
                            fprintf(stderr, "ERROR: can not read data from the file  %s\n", elf_name);
                            fclose(uf2_file);
                            return 26;
                        }
                        if(cur_mem->target_size < bytes_to_fill)
                        {
                            // last block
                            bytes_to_fill = cur_mem->target_size;
                        }
                        if(1 != fread(&buffer, bytes_to_fill, 1, elf_file))
                        {
                            fprintf(stderr, "ERROR: could not read data from %s !\n", elf_name);
                            fclose(uf2_file);
                            return 27;
                        }
                        memcpy(&UF2_Block.data[copy_size], buffer, bytes_to_fill);
                        UF2_Block.payloadSize = UF2_Block.payloadSize + bytes_to_fill;
                        cur_mem->target_size = cur_mem->target_size - bytes_to_fill;
                        cur_mem->target_start_addr = cur_mem->target_start_addr + bytes_to_fill;
                    }
                    // else not continuous
                }
                // else cur_mem = NULL -> already the last sector
            }

            if(1 != fwrite(&UF2_Block, sizeof(UF2_Block), 1, uf2_file))
            {
                fprintf(stderr, "ERROR: could not write data to %s !\n", uf2_name);
                fclose(uf2_file);
                return 19;
            }
            UF2_Block.blockNo = UF2_Block.blockNo + 1;
        }

        // switch to next memory area
        if(NULL != cur_mem)
        {
            cur_mem = cur_mem->next;
        }
    }
    fclose(uf2_file);
    return 0;
}

static void print_usage(void)
{
    fprintf(stderr, "elf2uf2     Version %s\n", VERSION_STRING);
    fprintf(stderr, "create a UF2 file from the contents of a elf file.\n");
    fprintf(stderr, "usage: elf2uf2 [ options] -f 0x12345678 -i file.elf [ -o file.uf2]\n");
    fprintf(stderr, "everything in [] is optional.\n");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "-v : verbose log messages\n");
    fprintf(stderr, "-f 0x12345678 : family id\n");
    fprintf(stderr, "-p 256 : payload size in bytes\n");
    fprintf(stderr, "-l : list all family ids\n");
    fprintf(stderr, "-i file.elf : elf file to read\n");
    fprintf(stderr, "-o file.uf2 : file to write to\n");
    fprintf(stderr, "if the file.uf2 is not given the uf2 file with have the same name as the elf file.\n");
}

static int parse_command_line_parameters(int argc, char *argv[])
{
    int option;
    char* test;

    while ((option = getopt(argc, argv, "vf:p:li:o:")) >= 0)
    {
        switch (option)
        {
        case 'v': verbose = true;
            break;

        case 'f' :
            fam_id = strtoll(optarg, &test, 16);
            if('\0' == *test)
            {
                // OK
            }
            else
            {
                fprintf(stderr, "ERROR: invalid family id %s !\n", optarg);
                return 1;
            }
           break;

        case 'p' :
            payload_size = strtol(optarg, &test, 10);
            if('\0' == *test)
            {
                if(payload_size < 477)
                {
                    // OK
                }
                else
                {
                    fprintf(stderr, "ERROR: payload size to big (is: %s, max= 476) !\n", optarg);
                    return 15;
                }
            }
            else
            {
                fprintf(stderr, "ERROR: invalid payload size %s !\n", optarg);
                return 2;
            }
           break;

        case 'l' : print_all_families();
           return -1;

        case 'i' : elf_name = optarg;
           break;

        case 'o' : uf2_name = optarg;
           break;

        case ':' : print_usage();
            return 3; // option that needs an argument did not have one.

        case '?' : print_usage();
            return 4; // unknown option passed
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    FILE* elf_file;
    unsigned int i;
    bool uf2_name_free = false;

    if(512 != sizeof(UF2_Block))
    {
        fprintf(stderr, "ERROR: compile issue - padding !\n");
        return -1;
    }

    // parse the command line parameters
    i = parse_command_line_parameters(argc, argv);
    if(0 < i)
    {
        // something went wrong -> exit
        return i;
    } else if(0 > i)
    {
        // we are already done
        return 0;
    }
    // else -> go on

    // do we now have everything we need to go on?
    if(NULL == elf_name)
    {
        fprintf(stderr, "ERROR: no elf file given !\n");
        print_usage();
        return 5;
    }
    if(0 == fam_id)
    {
        fprintf(stderr, "ERROR: no family id given !\n");
        print_usage();
        return 6;
    }
    if(NULL == uf2_name)
    {
        int len = strnlen(elf_name, 2048);
        if(2048 == len)
        {
            // too long
            fprintf(stderr, "ERROR: elf file name too long!\n");
            return 21;
        }
        uf2_name = malloc(len);
        if(NULL == uf2_name)
        {
            fprintf(stderr, "ERROR: malloc() failed! no free RAM ?\n");
            return 20;
        }
        uf2_name_free = true;
        strcpy(uf2_name, elf_name);
        uf2_name[len -3] = 'u';
        uf2_name[len -2] = 'f';
        uf2_name[len -1] = '2';
    }
    // OK we have all the informations needed.

    if(true == verbose)
    {
        report_family();
    }

    elf_file = fopen(elf_name, "rb");
    if(NULL == elf_file)
    {
        fprintf(stderr, "ERROR: could not read the elf file %s !\n", elf_name);
        if(true == uf2_name_free)
        {
            free(uf2_name);
        }
        return 7;
    }
    // read elf file header
    i = read_elf_file_header(elf_file);
    if(0 < i)
    {
        // something went wrong -> exit
        fclose(elf_file);
        if(true == uf2_name_free)
        {
            free(uf2_name);
        }
        return i;
    }
    // else -> go on
    i = read_program_table(elf_file);
    if(0 < i)
    {
        // something went wrong -> exit
        fclose(elf_file);
        if(true == uf2_name_free)
        {
            free(uf2_name);
        }
        return i;
    }
    i = copy_data(elf_file);
    fclose(elf_file);
    if(0 < i)
    {
        // something went wrong -> exit
        if(true == uf2_name_free)
        {
            free(uf2_name);
        }
        return i;
    }

    if(true == uf2_name_free)
    {
        free(uf2_name);
    }
    if(true == verbose)
    {
        printf("Finished: success!\n");
    }
    return 0;
}
