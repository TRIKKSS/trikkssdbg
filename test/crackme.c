#include <stdio.h>
#include <string.h>

int main(void)
{
	char buffer[40];
	
	printf("enter your password : ");
	scanf("%39s", &buffer);

	if (strcmp(buffer, "secret_password") == 0)
	{
		printf("you find my password !\n");
	} else {
		printf("wrong password\n");
	}
	return 0;
}