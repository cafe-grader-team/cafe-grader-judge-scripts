#include <stdio.h>
#include <stdlib.h>

int main()
{
  int a,b;

  int c=0;

  scanf("%d %d",&a,&b);
  printf("%d\n",a+b);

  for(a=0; a<2; a++) {
    while(c<1550000000) {
      c++;
      b+=c;
    }
  }
  exit(0);
}

