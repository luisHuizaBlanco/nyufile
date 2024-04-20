#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

void validate()
{
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");

    exit(0);
}

void print_disk(char *diskname)
{
    int fd;
    unsigned char *addr;
    size_t length;
    struct stat sb;
    int FATs, bytes_p_sector, sectors_p_cluster, reserved_sec;
    struct BootEntry *boot;

    fd = open(diskname, O_RDWR);

    if (fd == -1)
    {
        exit(0);
    }
    
    if (fstat(fd, &sb) == -1) 
    {
        exit(0);
    }

    length = sb.st_size;         

    addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED)
    {
        exit(0);
    }

    boot = (BootEntry *)(addr);

    FATs = (int)boot->BPB_NumFATs;
    bytes_p_sector = (int)boot->BPB_BytsPerSec;
    sectors_p_cluster = (int)boot->BPB_SecPerClus;
    reserved_sec = (int)boot->BPB_RsvdSecCnt;


    printf("Number of FATs = %d\n", FATs);
    printf("Number of bytes per sector = %d\n", bytes_p_sector);
    printf("Number of sectors per cluster = %d\n", sectors_p_cluster);
    printf("Number of reserved sectors = %d\n", reserved_sec);

    munmap(addr, length);
    close(fd);

    exit(0);

}

void list_disk(char *diskname)
{
    int fd;
    unsigned char *addr;
    size_t length;
    struct stat sb;
    struct BootEntry *boot;
    struct DirEntry *dir;
    int FATs, FATsize, bytes_p_sector, sectors_p_cluster, reserved_sec, root_cluster, root_dir;

    fd = open(diskname, O_RDWR);

    if (fd == -1)
    {
        exit(0);
    }
    
    if (fstat(fd, &sb) == -1) 
    {
        exit(0);
    }

    length = sb.st_size;         

    addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED)
    {
        exit(0);
    }

    boot = (BootEntry *)(addr);

    FATs = (int)boot->BPB_NumFATs;
    FATsize = (int)boot->BPB_FATSz32;
    bytes_p_sector = (int)boot->BPB_BytsPerSec;
    sectors_p_cluster = (int)boot->BPB_SecPerClus;
    reserved_sec = (int)boot->BPB_RsvdSecCnt;
    root_cluster = (int)boot->BPB_RootClus;

    root_dir = reserved_sec + (FATs * FATsize) + (root_cluster - 2);

    //printf("%d\n", root_dir);

    root_dir = (sectors_p_cluster * bytes_p_sector) * root_dir;

    //printf("%d\n", root_dir);

    dir = (DirEntry *)(addr + root_dir);

    char *name;
    int size, s_cluster, num_of_entries = 0;

    while(dir->DIR_Name[0] != '\0')
    {
        if(dir->DIR_Name[0] == 0xe5 || dir->DIR_Name[0] == 0x00)
        {
            dir++;
            continue;
        }

        name = (char *)dir->DIR_Name;
        size = (int)dir->DIR_FileSize;
        s_cluster = (int)((dir->DIR_FstClusHI << 16) + dir->DIR_FstClusLO);
        num_of_entries++;

        printf("%s", name);
        printf("%d", s_cluster);

        for(int i = 0; i < 11; i++){

            if(name[i] == 0x20 || i == 8)
            {
                if(size == 0 && s_cluster > 0)
                {
                    printf("/ (starting cluster = %d)\n", s_cluster);

                    break;
                }
                else if(size == 0 && s_cluster == 0)
                {
                    printf(" (size = %d)\n", size);

                    break;
                }
                else if(name[8] != 0x20)
                {
                    printf(".%c", name[8]);

                    if(name[9] != 0x20)
                    {
                        printf("%c", name[9]);

                        if(name[10] != 0x20)
                        {
                            printf("%c", name[10]);
                        }
                    }
                    
                    printf(" (size = %d, starting cluster = %d)\n", size, s_cluster);

                    break;                    
                }
                else
                {
                    printf(" (size = %d, starting cluster = %d)\n", size, s_cluster);

                    break;
                }
            }
            else
            {
                printf("%c", name[i]);
            }
        }

        dir++;
    }

    printf("Total number of entries = %d\n", num_of_entries);

    munmap(addr, length);
    close(fd);

    exit(0);

}

void restore_file()
{
    printf("recovery\n");

    exit(0);

}

void restore_file_with_sha()
{
    printf("sha recovery\n");

    exit(0);

}

void non_co_restore_file()
{
    printf("nonc recovery\n");

    exit(0);

}

int main(int argc, char *argv[])
{
    //char* disk_image, filename, sha;

    if(argc >= 3)
    {

        if(strncmp(argv[2], "-i", 2) == 0)
        {
            print_disk(argv[1]);
        }

        if(strncmp(argv[2], "-l", 2) == 0)
        {
            list_disk(argv[1]);
        }

        if(strncmp(argv[2], "-r", 2) == 0)
        {
            if(argc == 4)
            {
                restore_file();

            }

            if(argc == 6)
            {
                if(strncmp(argv[4], "-s", 2) == 0)
                {
                    restore_file_with_sha();
                }

            }

        }

        if(strncmp(argv[2], "-R", 2) == 0)
        {
            if(argc == 6)
            {
                if(strncmp(argv[4], "-s", 2) == 0)
                {
                    non_co_restore_file();
                }

            }
        }
    
    }

    validate();
}