#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
  int a,b;

  int c=0;

  scanf("%d %d",&a,&b);
  printf("%d\n",a+b);

  sleep(1);

  c = 0;
  while(c<1000000000) {
    c++;
    b+=c;
  }
  exit(0);
}

