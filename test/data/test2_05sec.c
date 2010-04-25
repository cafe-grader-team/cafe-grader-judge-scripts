#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <windows.h>

// run it for 0.5 s

double get_running_time()
{
  FILETIME creation_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;
  GetProcessTimes(GetCurrentProcess(),
		  &creation_time,
		  &exit_time,
		  &kernel_time,
		  &user_time);

  SYSTEMTIME sys_kernel_time;
  SYSTEMTIME sys_user_time;

  FileTimeToSystemTime(&kernel_time, &sys_kernel_time);
  FileTimeToSystemTime(&user_time, &sys_user_time);
  
  double time_used = 
    ((sys_kernel_time.wSecond + sys_kernel_time.wMilliseconds/1000.0) +
     (sys_user_time.wSecond + sys_user_time.wMilliseconds/1000.0));  
  return time_used;
}

int main()
{
  int a,b;

  int c=0;
  int r;

  r = scanf("%d %d",&a,&b);
  printf("%d\n",a+b);

  while(1) {
    c++;
    b+=c;
    while(c<100000) {
      c++;
      b+=c;
    }
    if(get_running_time() > 0.5)
      break;
  }
  printf("%d\n",b);
  exit(0);
}

