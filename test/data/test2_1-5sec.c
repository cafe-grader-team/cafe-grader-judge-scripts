#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>

int main()
{
  int a,b;

  int c=0;

  scanf("%d %d",&a,&b);
  printf("%d\n",a+b);

  struct rusage ru;

  while(1) {
    c++;
    b+=c;
    while(c<1000000000) {
      c++;
      b+=c;
    }
    getrusage(RUSAGE_SELF,&ru);
    if((ru.ru_utime.tv_sec + ru.ru_stime.tv_sec)>=1)
      break;
  }
  printf("%d\n",b);
  c=0;
  while(c<100000000) {
    c++;
    b+=c;
  }
  if(b==10)
    printf("hello\n");

  exit(0);
}

