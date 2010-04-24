/*

This is originally taken from Fossil Grader.  It is modified so that
it has the same interface as the sandbox module for Cafe Grader.  By
the way, the Cafe-Grader's sandbox module is from Moe grader,
distributed under GPL.

*/

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "execute.h"

char* input_filename = 0;
char* output_filename = 0;
double time_limit = 1;
int memory_limit = 16*1024*1024;  // in bytes
char* exe_filename = 0;

// process_argument takes an array of arguments starting from argv[0].
void process_argument(int argc, char* argv[])
{
  for(int i=0; i<argc; i++) {
    if(argv[i][0]=='-') {  // options
      char opt = argv[i][1];
      char* arg = argv[i+1];
      switch(argv[i][1]) {
      case 'i':
	input_filename = strdup(arg);
	break;
      case 'o':
	output_filename = strdup(arg);
	break;
      case 't':
	time_limit = atof(arg);
	break;
      case 'm':
	memory_limit = atoi(arg)*1024;  // in bytes
      }
      i++;  // skip over option
    } else {
      // not an option --> executable
      exe_filename = strdup(argv[i]);
    }
  }
}

void display_help()
{
  printf("Using: trun <executable>\n");
  printf("Options:\n");
  printf("   -i <input>\n");
  printf("   -o <output>\n");
  printf("   -t <time limit (in seconds)>\n");
  printf("   -m <memory limit (in kilobytes)>\n");
}

main(int argc, char* argv[])
{
  process_argument(argc-1, &argv[1]);
  if(exe_filename==0)
    display_help();
  else
    execute(exe_filename, input_filename, output_filename, 
	    time_limit, memory_limit);
}
