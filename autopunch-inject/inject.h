#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

int WINAPI my_WSARecvFrom(SOCKET s, LPWSABUF out_buffers, DWORD out_buffers_count, LPDWORD bytes_sent, LPDWORD flags, struct sockaddr *from, int *fromlen, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);
int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from, int *fromlen);
int WINAPI my_WSASendTo(SOCKET s, LPWSABUF buffers, DWORD buffers_count, LPDWORD bytes_sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED overlapped, 	LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);
int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
int WINAPI my_bind(SOCKET s, const struct sockaddr *name, int namelen);
int WINAPI my_closesocket(SOCKET s);
HANDLE WINAPI my_CreateIoCompletionPort(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads);

void load();
void unload();
