#include <windows.h>
#include <stdio.h>
#include <conio.h>

void main()
{
	for (int i = 0; ; ++i)
	{
		printf("test:: %d\n", i);
		Sleep(1000);
	}
}