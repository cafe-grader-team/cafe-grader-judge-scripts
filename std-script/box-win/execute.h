/*
  This sandbox module is from [Fossil
  grader](http://code.google.com/p/fossil-grader/).

  The code is a modification from an unknown source on the internet.

*/
#ifndef EXECUTE_H_INCLUDED
#define EXECUTE_H_INCLUDED

#define EXE_RESULT_OK       0
#define EXE_RESULT_TIMEOUT  1
#define EXE_RESULT_MEMORY   2
#define EXE_RESULT_ERROR    3

#ifdef __cplusplus
extern "C" {
#endif

int execute(char *exname, char *inname, char *outname, double t, int max_mem=0);

#ifdef __cplusplus
}
#endif

#endif
