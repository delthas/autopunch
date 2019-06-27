#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "inject.h"
#include <crtdbg.h>

#define FATAL(fmt, ...) \
	fprintf(stderr, "%d: " fmt "\n", __LINE__, ##__VA_ARGS__); \
	exit(1);

#define DEBUG(fmt, ...) fprintf(stderr, "%d: " fmt "\n", __LINE__, ##__VA_ARGS__);

void CALLBACK cb(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED lpOverlapped, DWORD dwFlags) {
	DEBUG("%lu %lu %zu %lu", dwError, cbTransferred, (size_t)lpOverlapped, dwFlags);
}

int main(int argc, char **argv) {
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	load();

	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		FATAL("WSAStartup: %d", WSAGetLastError())
	}

	SOCKET s1 = WSASocketW(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (s1 < 0) {
		FATAL("socket: %d", WSAGetLastError())
	}

	SOCKET s2 = WSASocketW(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (s2 < 0) {
		FATAL("socket: %d", WSAGetLastError())
	}

	struct sockaddr_in local1;
	local1.sin_family = AF_INET;
	local1.sin_addr.s_addr = htonl(127 << 24 | 1);
	local1.sin_port = htons(10001);

	if (my_bind(s1, (struct sockaddr *)&local1, sizeof(local1)) < 0) {
		FATAL("bind: %d", WSAGetLastError())
	}

	struct sockaddr_in local2;
	local2.sin_family = AF_INET;
	local2.sin_addr.s_addr = htonl(127 << 24 | 1);
	local2.sin_port = htons(10002);

	if (my_bind(s2, (struct sockaddr *)&local2, sizeof(local2)) < 0) {
		FATAL("bind: %d", WSAGetLastError())
	}

	char buf[8];
	memset(buf, 0xCC, sizeof(buf));
	WSABUF wsabuf[] = {(WSABUF){
											 .buf = buf,
											 .len = 3,
										 },
		(WSABUF){
			.buf = &buf[4],
			.len = 2,
		}};

	DEBUG("cd: %d", WSAGetLastError())
	if (my_WSASendTo(s1, wsabuf, sizeof(wsabuf) / sizeof(*wsabuf), NULL, 0, (struct sockaddr *)&local2, sizeof(local2), NULL, NULL) < 0
		&& WSAGetLastError() != ERROR_IO_PENDING) {
		FATAL("sendto: %d", WSAGetLastError())
	}

	struct sockaddr_in other;
	int other_len = sizeof(other);

	int flags = 0;
	int n;
	if (my_WSARecvFrom(s2, wsabuf, sizeof(wsabuf) / sizeof(*wsabuf), &n, &flags, (struct sockaddr *)&other, &other_len, NULL, cb) < 0
		&& WSAGetLastError() != ERROR_IO_PENDING) {
		FATAL("recvfrom: %d", WSAGetLastError())
	}

	DEBUG("cc %d", SleepEx(INFINITE, true))

	if (local1.sin_addr.S_un.S_addr != other.sin_addr.S_un.S_addr || local1.sin_port != other.sin_port) {
		FATAL("recvfrom: unknown addr: %d %d", other.sin_addr.S_un.S_addr, other.sin_port)
	}

	if (my_closesocket(s1) < 0) {
		FATAL("closesocket: %d", WSAGetLastError())
	}

	DEBUG("cc %d", n);

	WSACleanup();

	unload();

	return 0;
}
