#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

class shell
{
public:
	shell(char*, int);
	~shell();
};

