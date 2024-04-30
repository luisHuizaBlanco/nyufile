#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

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
    unsigned char *disk;
    size_t length;
    struct stat sb;
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

    disk = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk == MAP_FAILED)
    {
        exit(0);
    }

    boot = (BootEntry *)(disk);

    int FATs = (int)boot->BPB_NumFATs;
    int bytes_p_sector = (int)boot->BPB_BytsPerSec;
    int sectors_p_cluster = (int)boot->BPB_SecPerClus;
    int reserved_sec = (int)boot->BPB_RsvdSecCnt;


    printf("Number of FATs = %d\n", FATs);
    printf("Number of bytes per sector = %d\n", bytes_p_sector);
    printf("Number of sectors per cluster = %d\n", sectors_p_cluster);
    printf("Number of reserved sectors = %d\n", reserved_sec);

    munmap(disk, length);
    close(fd);

    exit(0);

}

void list_disk(char *diskname)
{
    int fd;
    unsigned char *disk;
    size_t length;
    struct stat sb;

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

    disk = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk == MAP_FAILED)
    {
        exit(0);
    }
    
    //boot directory
    struct BootEntry *boot;
    boot = (BootEntry *)(disk);

    //variables needed from the boot sector
    unsigned int FATs = (unsigned int)boot->BPB_NumFATs;
    unsigned int FATsize = boot->BPB_FATSz32;
    unsigned int bytes_p_sector = (unsigned int)boot->BPB_BytsPerSec;
    unsigned int sectors_p_cluster = (unsigned int)boot->BPB_SecPerClus;
    unsigned int reserved_sec = (unsigned int)boot->BPB_RsvdSecCnt;
    unsigned int root_cluster = boot->BPB_RootClus;
    unsigned int bytes_p_cluster = bytes_p_sector * sectors_p_cluster;

    //offsets for the FAT table and directory
    unsigned int FAT_Table = reserved_sec * bytes_p_sector;
    unsigned int Data_Region = ((FATs * FATsize) * bytes_p_sector) + FAT_Table;
    unsigned int dir_start = Data_Region + ((root_cluster - 2) * bytes_p_cluster);

    // printf("%d\n", Data_Region);
    // printf("%d\n", dir_start);

    struct DirEntry *dir;
    dir = (DirEntry *)(disk + dir_start);

    //variables for directory entries
    char *name;
    unsigned int size = 0;
    unsigned int s_cluster = 0; 
    unsigned int num_of_entries = 0; 
    unsigned int entries_in_cluster = 0;
    unsigned int max_entries_in_cluster = bytes_p_cluster/sizeof(DirEntry);
    unsigned int offset_to_next_cluster = 0;
    unsigned int current_cluster = root_cluster;
    uint32_t EndOfFile = 0x0fffffff;

    while(dir->DIR_Name[0] != '\0')
    {
        //updating variables
        name = (char *)dir->DIR_Name;
        size = dir->DIR_FileSize;
        s_cluster = (unsigned int)((dir->DIR_FstClusHI << 16) + dir->DIR_FstClusLO);

        //skip deleted files
        if(dir->DIR_Name[0] == 0xe5)
        {
            entries_in_cluster++;

            if(entries_in_cluster == max_entries_in_cluster)
            {
                //check if next cluster is EOF
                uint32_t *ptr = (uint32_t *)&disk[FAT_Table + (4 * current_cluster)];
                uint32_t cluster_value = *ptr;

                if(cluster_value == EndOfFile || cluster_value == 0x00)
                {
                    break;
                }
                //go to next cluster
                current_cluster = cluster_value;
                offset_to_next_cluster = (current_cluster - 2) * bytes_p_cluster;
                dir = (DirEntry *)(disk + (dir_start + offset_to_next_cluster));
                entries_in_cluster = 0;

                continue;
                
            }
            else
            {
                dir++;
            }

            continue;
        }
        else
        {
            num_of_entries++;
        }

        for(int i = 0; i < 11; i++){

            if(name[i] == 0x20 || i == 8)
            {
                if(size == 0 && s_cluster > 0)
                {
                    printf("/ (starting cluster = %d)\n", s_cluster);

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
                    
                    if(size == 0 && s_cluster == 0)
                    {
                        printf(" (size = %d)\n", size);

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
                    if(size == 0 && s_cluster == 0)
                    {
                        printf(" (size = %d)\n", size);

                        break;
                    }
                    else
                    {
                        printf(" (size = %d, starting cluster = %d)\n", size, s_cluster);

                        break;
                    }     
                }
            }
            else
            {
                printf("%c", name[i]);
            }
        }

        entries_in_cluster++;

        if(entries_in_cluster == max_entries_in_cluster)
        {
            //check if next cluster is EOF
            uint32_t *ptr = (uint32_t *)&disk[FAT_Table + (4 * current_cluster)];
            uint32_t cluster_value = *ptr;

            if(cluster_value == EndOfFile || cluster_value == 0x00)
            {
                break;
            }
            //go to next cluster
            current_cluster = cluster_value;
            offset_to_next_cluster = (current_cluster - 2) * bytes_p_cluster;
            dir = (DirEntry *)(disk + (dir_start + offset_to_next_cluster));
            entries_in_cluster = 0;

            continue;
        }

        dir++;
        
    }

    printf("Total number of entries = %d\n", num_of_entries);

    munmap(disk, length);
    close(fd);

    exit(0);

}

void restore_file(char *diskname, char *filename)
{
    int fd;
    unsigned char *disk;
    size_t length;
    struct stat sb;

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

    disk = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk == MAP_FAILED)
    {
        exit(0);
    }

    //boot directory
    struct BootEntry *boot;
    boot = (BootEntry *)(disk);

    //variables needed from the boot sector
    unsigned int FATs = (unsigned int)boot->BPB_NumFATs;
    unsigned int FATsize = boot->BPB_FATSz32;
    unsigned int bytes_p_sector = (unsigned int)boot->BPB_BytsPerSec;
    unsigned int sectors_p_cluster = (unsigned int)boot->BPB_SecPerClus;
    unsigned int reserved_sec = (unsigned int)boot->BPB_RsvdSecCnt;
    unsigned int root_cluster = boot->BPB_RootClus;
    unsigned int bytes_p_cluster = bytes_p_sector * sectors_p_cluster;

    //offsets for the FAT table and directory
    unsigned int FAT_Table = reserved_sec * bytes_p_sector;
    unsigned int Data_Region = ((FATs * FATsize) * bytes_p_sector);
    unsigned int dir_start = Data_Region + FAT_Table + ((root_cluster - 2) * bytes_p_cluster);

    // printf("%d\n", Data_Region);
    // printf("%d\n", dir_start);

    struct DirEntry *dir;
    dir = (DirEntry *)(disk + dir_start);

    //variables for directory entries
    char *name;
    unsigned int size = 0;
    unsigned int s_cluster = 0; 
    unsigned int num_of_entries = 0; 
    unsigned int entries_in_cluster = 0;
    unsigned int max_entries_in_cluster = bytes_p_cluster/sizeof(DirEntry);
    unsigned int offset_to_next_cluster = 0;
    unsigned int current_cluster = root_cluster;
    uint32_t EndOfFile = 0x0fffffff;

    //name parser
    const char dot[] = ".";
    char deleted_name[12];
    memset(deleted_name, ' ', 12);
    deleted_name[11] = '\0';
    
    //format the filename to be like the names in the directories
    char * search_file = strdup(filename);
    char * token = strtok(search_file, dot);
    int len = strlen(token);
    int first = 0;
    
    while (token != NULL) {

        if(first == 0)
        {
            for(int i = 0; i < len; i++)
            {
                deleted_name[i] = token[i];

            }

            first = 1;
        }
        else if(first == 1 && token != NULL)
        {
            len = strlen(token);

            for(int i = 0; i < len && i < 3; i++)
            {
                deleted_name[i + 8] = token[i];

            }
            first = 2;
        }
        
        token = strtok(NULL, dot);
    }

    int similar_files = 0;
    struct DirEntry *deleted;
    

    // printf("%s\n", deleted_name);

    while(dir->DIR_Name[0] != '\0')
    {
        name = (char *)dir->DIR_Name;
        num_of_entries++;

        if(dir->DIR_Name[0] == 0xe5)
        {
            // printf("%s\n", name);
            // printf("%s\n", deleted_name);

            if(strncmp(name + 1, deleted_name + 1, 10) == 0)
            {
                deleted = dir;

                similar_files++;
            }
        }

        entries_in_cluster++;

        if(entries_in_cluster == max_entries_in_cluster)
        {
            //check if next cluster is EOF
            uint32_t *ptr = (uint32_t *)&disk[FAT_Table + (4 * current_cluster)];
            uint32_t cluster_value = *ptr;

            if(cluster_value == EndOfFile)
            {
                break;
            }
            //go to next cluster
            current_cluster = cluster_value;
            offset_to_next_cluster = (current_cluster - 2) * bytes_p_cluster;
            dir = (DirEntry *)(disk + (dir_start + offset_to_next_cluster));
            entries_in_cluster = 0;

            continue;
        }

        dir++;
        
    }

    if(similar_files > 1)
    {
        printf("%s: multiple candidates found\n", filename);
    }
    else if(similar_files == 1)
    {
        deleted->DIR_Name[0] = filename[0];

        size = deleted->DIR_FileSize;
        s_cluster = (unsigned int)((deleted->DIR_FstClusHI << 16) + deleted->DIR_FstClusLO);

        unsigned int num_of_cluster = 0;
        num_of_cluster = size / bytes_p_cluster;

        if(size % bytes_p_cluster != 0)
        {
            num_of_cluster++;
        }

        uint32_t *ptr_to_deleted = (uint32_t *)&disk[FAT_Table + (4 * s_cluster)];
        uint32_t *ptr_to_deleted2;
        uint32_t deleted_cluster = (uint32_t)s_cluster;

        if(FATs == 2)
        {
            ptr_to_deleted2 = (uint32_t *)&disk[FAT_Table + (Data_Region/2) + (4 * s_cluster)];
        }

        // printf("%d\n", num_of_cluster);
        // printf("%d\n", FAT_Table + (4 * s_cluster));

        for(unsigned int i = 0; i < num_of_cluster; i++)
        {
            if(i == num_of_cluster - 1)
            {
                ptr_to_deleted[i] = EndOfFile;

                if(FATs == 2)
                {
                    ptr_to_deleted2[i] = EndOfFile;
                }
            }
            else
            {
                ptr_to_deleted[i] = deleted_cluster + i + 1;

                if(FATs == 2)
                {
                    ptr_to_deleted2[i] = deleted_cluster + i + 1;
                }
            }
        }

        printf("%s: successfully recovered\n", filename);
    }
    else
    {
        printf("%s: file not found\n", filename);
    }

    munmap(disk, length);
    free(search_file);
    close(fd);

    exit(0);

}

void restore_file_with_sha(char *diskname, char *filename, unsigned char * sha)
{
    int fd;
    unsigned char *disk;
    size_t length;
    struct stat sb;

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

    disk = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (disk == MAP_FAILED)
    {
        exit(0);
    }

    //boot directory
    struct BootEntry *boot;
    boot = (BootEntry *)(disk);

    //variables needed from the boot sector
    unsigned int FATs = (unsigned int)boot->BPB_NumFATs;
    unsigned int FATsize = boot->BPB_FATSz32;
    unsigned int bytes_p_sector = (unsigned int)boot->BPB_BytsPerSec;
    unsigned int sectors_p_cluster = (unsigned int)boot->BPB_SecPerClus;
    unsigned int reserved_sec = (unsigned int)boot->BPB_RsvdSecCnt;
    unsigned int root_cluster = boot->BPB_RootClus;
    unsigned int bytes_p_cluster = bytes_p_sector * sectors_p_cluster;

    //offsets for the FAT table and directory
    unsigned int FAT_Table = reserved_sec * bytes_p_sector;
    unsigned int Data_Region = ((FATs * FATsize) * bytes_p_sector);
    unsigned int dir_start = Data_Region + FAT_Table + ((root_cluster - 2) * bytes_p_cluster);

    // printf("%d\n", Data_Region);
    // printf("%d\n", dir_start);

    struct DirEntry *dir;
    dir = (DirEntry *)(disk + dir_start);

    //variables for directory entries
    char *name;
    unsigned int size = 0;
    unsigned int s_cluster = 0; 
    unsigned int num_of_entries = 0; 
    unsigned int entries_in_cluster = 0;
    unsigned int max_entries_in_cluster = bytes_p_cluster/sizeof(DirEntry);
    unsigned int offset_to_next_cluster = 0;
    unsigned int current_cluster = root_cluster;
    uint32_t EndOfFile = 0x0fffffff;

    //name parser
    const char dot[] = ".";
    char deleted_name[12];
    memset(deleted_name, ' ', 12);
    deleted_name[11] = '\0';
    
    //format the filename to be like the names in the directories
    char * search_file = strdup(filename);
    char * token = strtok(search_file, dot);
    int len = strlen(token);
    int first = 0;

    //unsigned char empty[SHA_DIGEST_LENGTH + 1] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    unsigned char * buffer = NULL;
    
    while (token != NULL) {

        if(first == 0)
        {
            for(int i = 0; i < len; i++)
            {
                deleted_name[i] = token[i];

            }

            first = 1;
        }
        else if(first == 1 && token != NULL)
        {
            len = strlen(token);

            for(int i = 0; i < len && i < 3; i++)
            {
                deleted_name[i + 8] = token[i];

            }
            first = 2;
        }
        
        token = strtok(NULL, dot);
    }

    struct DirEntry *deleted = NULL;

    while(dir->DIR_Name[0] != '\0')
    {
        name = (char *)dir->DIR_Name;
        num_of_entries++;

        if(dir->DIR_Name[0] == 0xe5)
        {

            if(strncmp(name + 1, deleted_name + 1, 10) == 0)
            {
                s_cluster = (unsigned int)((dir->DIR_FstClusHI << 16) + dir->DIR_FstClusLO);

                SHA1(disk + dir_start + (s_cluster * bytes_p_cluster), dir->DIR_FileSize, buffer);

                // printf("%s\n", buffer);
                // printf("%s\n", sha);

                if((strncmp((char *) buffer, (char *) sha, SHA_DIGEST_LENGTH)) == 0 )
                {
                    deleted = dir;
                }
            }
        }

        entries_in_cluster++;

        if(entries_in_cluster == max_entries_in_cluster)
        {
            //check if next cluster is EOF
            uint32_t *ptr = (uint32_t *)&disk[FAT_Table + (4 * current_cluster)];
            uint32_t cluster_value = *ptr;

            if(cluster_value == EndOfFile)
            {
                break;
            }
            //go to next cluster
            current_cluster = cluster_value;
            offset_to_next_cluster = (current_cluster - 2) * bytes_p_cluster;
            dir = (DirEntry *)(disk + (dir_start + offset_to_next_cluster));
            entries_in_cluster = 0;

            continue;
        }

        dir++;
        
    }

    if(deleted != NULL)
    {
        deleted->DIR_Name[0] = filename[0];

        size = deleted->DIR_FileSize;
        s_cluster = (unsigned int)((deleted->DIR_FstClusHI << 16) + deleted->DIR_FstClusLO);

        unsigned int num_of_cluster = 0;
        num_of_cluster = size / bytes_p_cluster;

        if(size % bytes_p_cluster != 0)
        {
            num_of_cluster++;
        }

        uint32_t *ptr_to_deleted = (uint32_t *)&disk[FAT_Table + (4 * s_cluster)];
        uint32_t *ptr_to_deleted2;
        uint32_t deleted_cluster = (uint32_t)s_cluster;

        if(FATs == 2)
        {
            ptr_to_deleted2 = (uint32_t *)&disk[FAT_Table + (Data_Region/2) + (4 * s_cluster)];
        }

        // printf("%d\n", num_of_cluster);
        // printf("%d\n", FAT_Table + (4 * s_cluster));

        for(unsigned int i = 0; i < num_of_cluster; i++)
        {
            if(i == num_of_cluster - 1)
            {
                ptr_to_deleted[i] = EndOfFile;

                if(FATs == 2)
                {
                    ptr_to_deleted2[i] = EndOfFile;
                }
            }
            else
            {
                ptr_to_deleted[i] = deleted_cluster + i + 1;

                if(FATs == 2)
                {
                    ptr_to_deleted2[i] = deleted_cluster + i + 1;
                }
            }
        }

        printf("%s: successfully recovered with SHA-1\n", filename);
    }
    else
    {
        printf("%s: file not found\n", filename);
    }

    munmap(disk, length);
    free(search_file);
    close(fd);

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
                restore_file(argv[1], argv[3]);

            }

            if(argc == 6)
            {
                if(strncmp(argv[4], "-s", 2) == 0)
                {
                    restore_file_with_sha(argv[1], argv[3], (unsigned char *) argv[5]);
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