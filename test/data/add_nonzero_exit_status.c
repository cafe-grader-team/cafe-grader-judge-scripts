#include <stdio.h>

int main()
{
  int a,b;
  int r;
  r = scanf("%d %d",&a,&b);
  printf("%d\n",a+b);
  a+=r;
  return 10;
}

