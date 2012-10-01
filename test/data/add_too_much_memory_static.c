#include <stdio.h>

int big_array[2000000];

int main()
{
  int a,b;
  int r;
  r = scanf("%d %d",&a,&b);
  printf("%d\n",a+b);
  a += r;
  return 0;
}

