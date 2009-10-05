#include <stdio.h>

main()
{
  int n, x, total;
  int i;
  scanf("%d",&n);
  total = 0;
  for(i=0; i<n; i++) {
    scanf("%d",&x);
    total += x;
  }
  printf("%d\n",total);
}
