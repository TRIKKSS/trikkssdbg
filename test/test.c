#include <stdio.h>

/*
just a binary used to test my debugger.
*/

int main(void)
{
	while(1){
		printf("hello world !!\n");
		__asm__("int3");
	}
}
