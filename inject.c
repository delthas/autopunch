#pragma ide diagnostic ignored "hicpp-signed-bitwise"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <detours.h>
#include <shlobj.h>

#ifndef NDEBUG
	#define DEBUG 1
	#define DEBUG_LOG(fmt, ...) \
		fprintf(debug, "%d: " fmt "\n", __LINE__, ##__VA_ARGS__); \
		fflush(debug);
	#define DEBUG_ADDR(fmt, addr, ...) \
		fprintf(debug, "%d: " fmt " %d.%d.%d.%d\n", __LINE__, ##__VA_ARGS__, addr.S_un.S_un_b.s_b1, addr.S_un.S_un_b.s_b2, addr.S_un.S_un_b.s_b3, addr.S_un.S_un_b.s_b4); \
		fflush(debug);
#else
	#define DEBUG 0
	#define DEBUG_LOG(fmt, ...);
	#define DEBUG_ADDR(fmt, addr, ...);
#endif

#define WARN(fmt, ...) { \
	size_t needed = _snwprintf(NULL, 0, fmt, ##__VA_ARGS__); \
	wchar_t *buf = malloc((needed + 1) * 2); \
	_snwprintf(buf, (needed + 1), fmt, ##__VA_ARGS__); \
	MessageBoxW(NULL, buf, L"autopunch", MB_ICONWARNING | MB_OK); \
	free(buf); \
}

const wchar_t relay_host[] = L"delthas.fr";
const int relay_port = 14763;
struct sockaddr_in relay_addr;
const char punch_payload[] = {0};

FILE *debug;

struct mapping {
	struct sockaddr_in addr;
	u_short port;
	clock_t last_send;
	clock_t last_refresh;
	bool refresh;
};

struct transient_peer {
	struct sockaddr_in addr;
	clock_t last;
};

struct socket_data {
	SOCKET s;
	HANDLE mutex;
	u_short port;
	bool closed;
	struct mapping *mappings;
	size_t mappings_len;
	size_t mappings_cap;
	struct transient_peer *transient_peers;
	size_t transient_peers_len;
	size_t transient_peers_cap;
};

struct socket_data *sockets;
size_t sockets_len;
size_t sockets_cap;
HANDLE sockets_mutex;

HANDLE relay_thread;
bool relay_close;

int(WINAPI *actual_recvfrom)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) = recvfrom;
int(WINAPI *actual_sendto)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) = sendto;
int(WINAPI *actual_bind)(SOCKET s, const struct sockaddr *name, int namelen) = bind;
int(WINAPI *actual_closesocket)(SOCKET s) = closesocket;

u_long get_relay_ip() {
	ADDRINFOW hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	ADDRINFOW *result = NULL;
	DWORD r = GetAddrInfoW(relay_host, NULL, &hints, &result);
	if(r != 0) {
		DEBUG_LOG("getaddrinfow failed: %lu", r);
		return 0;
	}
	for(ADDRINFOW *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		if(ptr->ai_family == AF_INET) {
			u_long address = ((struct sockaddr_in*)ptr->ai_addr)->sin_addr.s_addr;
			FreeAddrInfoW(result);
			DEBUG_LOG("getaddrinfow success: %lu", address);
			return address;
		}
	}
	FreeAddrInfoW(result);
	DEBUG_LOG("getaddrinfow nothing: 0");
	return 0;
}

DWORD WINAPI relay(void *data) {
	while (!relay_close) {
		WaitForSingleObject(sockets_mutex, INFINITE);
		clock_t now = clock();
		if(relay_addr.sin_addr.s_addr == 0) {
			relay_addr.sin_addr.s_addr = get_relay_ip();
		}
		for (int i = 0; i < sockets_len; ++i) {
			struct socket_data *socket_data = &sockets[i];
			WaitForSingleObject(socket_data->mutex, INFINITE);
			if (socket_data->closed) {
				DEBUG_LOG("relay remove closed socket socket=%zu mappings=%zu closed=%d, len=%zu cap=%zu", socket_data->s, (size_t)socket_data->mappings, socket_data->closed,
					socket_data->mappings_len, socket_data->mappings_cap)
				ReleaseMutex(socket_data->mutex);
				CloseHandle(socket_data->mutex);
				free(socket_data->mappings);
				free(socket_data->transient_peers);
				sockets[i--] = sockets[--sockets_len];
				continue;
			}
			char buf[] = {((char*)&(socket_data->port))[0], ((char*)&(socket_data->port))[1]};
			DEBUG_LOG("relay sendto i=%d local port=%u socket=%zu %d %d", i, ntohs(socket_data->port), socket_data->s, buf[0], buf[1])
			actual_sendto(socket_data->s, buf, sizeof(buf), 0, (struct sockaddr *)&relay_addr, sizeof(relay_addr));
			for (int j = 0; j < socket_data->mappings_len; ++j) {
				struct mapping *mapping = &socket_data->mappings[j];
				clock_t wait_refresh = (now - mapping->last_refresh) / CLOCKS_PER_SEC;
				DEBUG_LOG("relay mappinglist i=%d j=%d wait_refresh=%ld", i, j, wait_refresh)
				if (wait_refresh > 10) { // drop old mapping
					DEBUG_LOG("relay mappinglist timeout %d %d %ld", i, j, wait_refresh)
					socket_data->mappings[j--] = socket_data->mappings[--socket_data->mappings_len];
					continue;
				}
				clock_t wait_send = (now - mapping->last_send) / CLOCKS_PER_SEC;
				if (mapping->refresh && wait_send > 1) { // refresh mapping
					DEBUG_LOG("relay mappinglist refresh i=%d j=%d wait=%ld socket=%zu", i, j, wait_send, socket_data->s)
					actual_sendto(socket_data->s, punch_payload, sizeof(punch_payload), 0, (struct sockaddr *)&mapping->addr, sizeof(mapping->addr));
					mapping->last_send = clock();
				}
			}
			ReleaseMutex(socket_data->mutex);
		}
		ReleaseMutex(sockets_mutex);
		if (relay_close) {
			return 0;
		}
		Sleep(500);
	}
	return 0;
}

int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from, int *fromlen) {
	struct sockaddr_in *addr = (struct sockaddr_in *)from;
	struct socket_data *socket_data = NULL;
	WaitForSingleObject(sockets_mutex, INFINITE);
	for (int i = 0; i < sockets_len; ++i) {
		socket_data = &sockets[i];
		if (socket_data->s == s) {
			break;
		}
	}
	ReleaseMutex(sockets_mutex);
	if (!socket_data) {
		DEBUG_LOG("recvfrom error unknown socket")
		return actual_recvfrom(s, out_buf, len, flags, from, fromlen); // TODO error handling
	}
	
	char *buf;
	if(len < 8) {
		buf = malloc(8);
	} else {
		buf = out_buf;
	}
	DEBUG_LOG("recvfrom_start len=%d flags=%d", len, flags)
	while (true) {
		int n = actual_recvfrom(s, buf, len > 8 ? len : 8, flags, from, fromlen);
		DEBUG_LOG("recvfrom actual n=%d", n)
		if (n < 0) {
			int err = WSAGetLastError();
			if (err == WSAECONNRESET) { // ignore connection reset errors (can happen if relay is down)
				DEBUG_LOG("recvfrom skipped error=%d", err)
				continue;
			}
			DEBUG_LOG("recvfrom error=%d", err)
			return err;
		}
		if (addr->sin_addr.s_addr == relay_addr.sin_addr.s_addr && addr->sin_port == relay_addr.sin_port) {
			if (n % 8) {
				DEBUG_LOG("recvfrom error receive size n=%d", n)
				continue;
			}
			WaitForSingleObject(socket_data->mutex, INFINITE);
			clock_t now = clock();
			u_short port_internal = *((u_short*)(&buf[0]));
			u_short port = *((u_short*)(&buf[2]));
			struct in_addr addr = {.s_addr = *(u_long*)(&buf[4])};
			DEBUG_LOG("recvfrom mapping port=%d nat_port=%d", ntohs(port_internal), ntohs(port))
			for (int j = 0; j < socket_data->mappings_len; ++j) {
				struct mapping *mapping = &socket_data->mappings[j];
				if (mapping->addr.sin_addr.s_addr != addr.s_addr) {
					continue;
				}
				if (mapping->port != port_internal) {
					continue;
				}
				DEBUG_LOG("recvfrom mapping replaced old_port=%d old_nat_port=%d", ntohs(mapping->port), ntohs(mapping->addr.sin_port))
				mapping->addr.sin_port = port;
				mapping->last_refresh = now;
				mapping->last_send = now;
				goto outer;
			}
			if (socket_data->mappings_len == socket_data->mappings_cap) {
				socket_data->mappings_cap = socket_data->mappings_cap ? socket_data->mappings_cap * 2 : 8;
				socket_data->mappings = realloc(socket_data->mappings, socket_data->mappings_cap * sizeof(socket_data->mappings[0]));
			}
			socket_data->mappings[socket_data->mappings_len++] = (struct mapping) {
				.addr = (struct sockaddr_in) {
					.sin_family = AF_INET,
					.sin_port = port,
					.sin_addr.s_addr = addr.s_addr,
				},
				.port = port_internal,
				.last_refresh = now,
				.last_send = now,
				.refresh = true,
			};
			DEBUG_LOG("recvfrom mapping added mappings_len=%zu mappings_cap=%zu", socket_data->mappings_len, socket_data->mappings_cap)
			outer:;
			ReleaseMutex(socket_data->mutex);
			continue;
		}
		
		WaitForSingleObject(socket_data->mutex, INFINITE);
		for (int i = 0; i < socket_data->transient_peers_len; ++i) {
			struct transient_peer *peer = &socket_data->transient_peers[i];
			if (peer->addr.sin_addr.s_addr != addr->sin_addr.s_addr) {
				continue;
			}
			if (peer->addr.sin_port != addr->sin_port) {
				DEBUG_LOG("recvfrom transient port mismatch transient=%d dest=%d", ntohs(peer->addr.sin_port), ntohs(addr->sin_port))
				continue;
			}
			socket_data->transient_peers[i--] = socket_data->transient_peers[--socket_data->transient_peers_len];
			
			if (socket_data->mappings_len == socket_data->mappings_cap) {
				socket_data->mappings_cap = socket_data->mappings_cap ? socket_data->mappings_cap * 2 : 8;
				socket_data->mappings = realloc(socket_data->mappings, socket_data->mappings_cap * sizeof(socket_data->mappings[0]));
			}
			clock_t now = clock();
			socket_data->mappings[socket_data->mappings_len++] = (struct mapping) {
				.addr = (struct sockaddr_in) {
					.sin_family = AF_INET,
					.sin_port = addr->sin_port,
					.sin_addr.s_addr = addr->sin_addr.s_addr,
				},
				.port = addr->sin_port,
				.last_refresh = now,
				.last_send = now,
				.refresh = false,
			};
			DEBUG_LOG("recvfrom matched transient added mappings_len=%zu mappings_cap=%zu", socket_data->mappings_len, socket_data->mappings_cap)
		}
		
		if(n == sizeof(punch_payload) && !memcmp(punch_payload, buf, n)) {
			DEBUG_LOG("recvfrom skipped received punch payload")
			continue;
		}
		
		for (int i = 0; i < socket_data->mappings_len; ++i) {
			struct mapping *mapping = &socket_data->mappings[i];
			if (mapping->addr.sin_addr.s_addr != addr->sin_addr.s_addr) {
				continue;
			}
			if (mapping->addr.sin_port != addr->sin_port) {
				DEBUG_LOG("recvmfrom mapping port mismatch mapping=%d dest=%d", ntohs(mapping->addr.sin_port), ntohs(addr->sin_port))
				continue;
			}
			DEBUG_LOG("recvmfrom mapping used old=%d replaced=%d", ntohs(addr->sin_port), ntohs(mapping->addr.sin_port))
			addr->sin_port = mapping->port;
			break;
		}
		ReleaseMutex(socket_data->mutex);
		
		DEBUG_ADDR("recvfrom actualdata n=%d buf[0]=%d from=%d@", addr->sin_addr, n, buf[0], addr->sin_port)
		if(out_buf != buf) {
			memcpy(out_buf, buf, n);
		}
		return n;
	}
}

int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
	if(len) {
		DEBUG_LOG("sendto start socket=%zu len=%d buf[0]=%d", s, len, buf[0])
	} else {
		DEBUG_LOG("sendto start socket=%zu len=%d (empty)", s, len)
	}
	if (to->sa_family != AF_INET) {
		DEBUG_LOG("sendto mapping sa_family != AF_INET: %d", to->sa_family)
		return actual_sendto(s, buf, len, flags, to, tolen);
	}
	struct socket_data *socket_data = NULL;
	WaitForSingleObject(sockets_mutex, INFINITE);
	for (int i = 0; i < sockets_len; ++i) {
		socket_data = &sockets[i];
		if (socket_data->s == s) {
			break;
		}
	}
	ReleaseMutex(sockets_mutex);
	if (!socket_data) {
		DEBUG_LOG("sendto error unknown socket")
		return actual_sendto(s, buf, len, flags, to, tolen); // TODO error?
	}
	WaitForSingleObject(socket_data->mutex, INFINITE);
	const struct sockaddr_in *dest = (const struct sockaddr_in *)to;
	for (int i = 0; i < socket_data->mappings_len; ++i) {
		struct mapping *mapping = &socket_data->mappings[i];
		if (mapping->addr.sin_addr.s_addr != dest->sin_addr.s_addr) {
			continue;
		}
		if (mapping->port != dest->sin_port) {
			DEBUG_LOG("sendto mapping port mismatch mapping=%d dest=%d", ntohs(mapping->port), ntohs(dest->sin_port))
			continue;
		}
		clock_t now = clock();
		mapping->last_refresh = now;
		mapping->last_send = now;
		DEBUG_LOG("sendto mapping used old=%d replaced=%d", ntohs(dest->sin_port), ntohs(mapping->addr.sin_port))
		int r = actual_sendto(s, buf, len, flags, (struct sockaddr *)mapping, tolen);
		ReleaseMutex(socket_data->mutex);
		return r;
	}
	DEBUG_LOG("sendto unknown mapping for port=%d sending to peer and relay", ntohs(dest->sin_port))
	int r = actual_sendto(s, buf, len, flags, to, tolen);
	
	int refresh = -1;
	clock_t now = clock();
	for (int i = 0; i < socket_data->transient_peers_len; ++i) {
		struct transient_peer *peer = &socket_data->transient_peers[i];
		if((now - peer->last) / CLOCKS_PER_SEC > 10) { // transient peer timeout
			socket_data->transient_peers[i--] = socket_data->transient_peers[--socket_data->transient_peers_len];
			continue;
		}
		if (peer->addr.sin_addr.s_addr != dest->sin_addr.s_addr) {
			continue;
		}
		if (peer->addr.sin_port != dest->sin_port) {
			DEBUG_LOG("sendto transient port mismatch transient=%d dest=%d", ntohs(peer->addr.sin_port), ntohs(dest->sin_port))
			continue;
		}
		refresh = (now - peer->last) * 1000 / CLOCKS_PER_SEC > 500;
		if(refresh) {
			peer->last = now;
		}
		DEBUG_LOG("sendto transient found, refresh=%d now=%ld last=%ld", refresh, now, peer->last)
	}
	if(refresh == -1) {
		if (socket_data->transient_peers_len == socket_data->transient_peers_cap) {
			socket_data->transient_peers_cap = socket_data->transient_peers_cap ? socket_data->transient_peers_cap * 2 : 8;
			socket_data->transient_peers = realloc(socket_data->transient_peers, socket_data->transient_peers_cap * sizeof(socket_data->transient_peers[0]));
		}
		socket_data->transient_peers[socket_data->transient_peers_len++] = (struct transient_peer) {
			.addr = (struct sockaddr_in) {
				.sin_family = AF_INET,
				.sin_port = dest->sin_port,
				.sin_addr.s_addr = dest->sin_addr.s_addr,
			},
			.last = now,
		};
		refresh = true;
		DEBUG_LOG("sendto transient created len=%zu cap=%zu", socket_data->transient_peers_len, socket_data->transient_peers_cap)
	}
	
	if(refresh) {
		char relay_buf[] = {((char*)&(socket_data->port))[0], ((char*)&(socket_data->port))[1], dest->sin_addr.S_un.S_un_b.s_b1, dest->sin_addr.S_un.S_un_b.s_b2,
												dest->sin_addr.S_un.S_un_b.s_b3, dest->sin_addr.S_un.S_un_b.s_b4, ((char*)&(dest->sin_port))[0], ((char*)&(dest->sin_port))[1]};
		actual_sendto(s, relay_buf, sizeof(relay_buf), 0, (struct sockaddr *)&relay_addr, sizeof(relay_addr));
		DEBUG_LOG("sendto transient refreshed; sent to relay")
	}
	ReleaseMutex(socket_data->mutex);
	return r;
}

int WINAPI my_bind(SOCKET s, const struct sockaddr *name, int namelen) {
	DEBUG_LOG("bind start for socket=%zu", s)
	if (name) {
		DEBUG_ADDR("bind request ip is %d @ ", ((const struct sockaddr_in *)name)->sin_addr, ntohs(((const struct sockaddr_in *)name)->sin_port))
	} else {
		DEBUG_LOG("bind request ip is null")
	}
	int r = actual_bind(s, name, namelen);
	if (r) {
		DEBUG_LOG("bind actual failed %d", r)
		return r;
	}
	struct sockaddr_in local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	if (getsockname(s, (struct sockaddr *)&local_addr, &local_addr_len)) {
		DEBUG_LOG("bind getsockname error %d", WSAGetLastError())
		return r;
	}
	if (local_addr.sin_family != AF_INET) {
		DEBUG_LOG("bind getsockname socket is not AF_INET %d", local_addr.sin_family)
		return r;
	}
	DEBUG_LOG("bind local port is %d %d", local_addr.sin_family, ntohs(local_addr.sin_port))
	WaitForSingleObject(sockets_mutex, INFINITE);
	if (sockets_len == sockets_cap) {
		sockets_cap = sockets_cap ? sockets_cap * 2 : 8;
		sockets = realloc(sockets, sockets_cap * sizeof(sockets[0]));
	}
	sockets[sockets_len++] = (struct socket_data){
		.s = s,
		.port = local_addr.sin_port,
		.mutex = CreateMutex(NULL, FALSE, NULL),
	};
	DEBUG_LOG("bind add socket socket=%zu mappings=%zu closed=%d, len=%zu cap=%zu", sockets[sockets_len - 1].s, (size_t)sockets[sockets_len - 1].mappings,
		sockets[sockets_len - 1].closed, sockets[sockets_len - 1].mappings_len, sockets[sockets_len - 1].mappings_cap)
	DEBUG_LOG("bind added socket %zu, len=%zu cap=%zu", s, sockets_len, sockets_cap)
	ReleaseMutex(sockets_mutex);
	return r;
}

int WSAAPI my_closesocket(SOCKET s) {
	DEBUG_LOG("close start socket=%zu", s)
	int r = actual_closesocket(s);
	if (r) {
		DEBUG_LOG("close error=%d", WSAGetLastError());
	}
	struct socket_data *socket_data = NULL;
	WaitForSingleObject(sockets_mutex, INFINITE);
	for (int i = 0; i < sockets_len; ++i) {
		socket_data = &sockets[i];
		if (socket_data->s == s) {
			break;
		}
	}
	ReleaseMutex(sockets_mutex);
	if (!socket_data) {
		DEBUG_LOG("close error unknown socket, err=%d", r)
		return r;
	}
	WaitForSingleObject(socket_data->mutex, INFINITE);
	socket_data->closed = true;
	ReleaseMutex(socket_data->mutex);
	DEBUG_LOG("close end")
	return r;
}

const wchar_t *inject_log_prefix = L"\\inject.";
const wchar_t *inject_log_suffix = L"\\.log";

void load() {
	if(DEBUG) {
		srand(time(NULL));
		wchar_t *desktop_path = malloc((MAX_PATH + 1) * 2);
		SHGetSpecialFolderPathW(HWND_DESKTOP, desktop_path, CSIDL_DESKTOP, FALSE);
		wchar_t *path = malloc((MAX_PATH + 1) * 2);
		_snwprintf(path, MAX_PATH + 1, L"%ls\\inject.%d.log", desktop_path, rand() % 1000000);
		free(desktop_path);
		WARN(L"Injected autopunch with debug!\nPath to debug is: %ls", path)
		debug = _wfopen(path, L"w");
		free(path);
	}

	DEBUG_LOG("load_start")

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((void **)&actual_recvfrom, my_recvfrom);
	DetourAttach((void **)&actual_sendto, my_sendto);
	DetourAttach((void **)&actual_bind, my_bind);
	DetourAttach((void **)&actual_closesocket, my_closesocket);
	DetourTransactionCommit();

	u_long relay_ip_net = get_relay_ip();
	u_short relay_port_net = htons(relay_port);
	relay_addr = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = relay_port_net, .sin_addr.s_addr = relay_ip_net};

	sockets_mutex = CreateMutex(NULL, FALSE, NULL);
	relay_thread = CreateThread(NULL, 0, relay, NULL, 0, NULL);

	DEBUG_LOG("load_end")
}

void unload() {
	DEBUG_LOG("unload_start")

	relay_close = true;
	WaitForSingleObject(sockets_mutex, INFINITE);
	CloseHandle(relay_thread);
	ReleaseMutex(sockets_mutex);
	CloseHandle(sockets_mutex);
	DEBUG_LOG("unload_free %zu %zu %zu", sockets_len, sockets_cap, (size_t)sockets)
	free(sockets);
	
	DEBUG_LOG("unload_detours")
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((void **)&actual_recvfrom, my_recvfrom);
	DetourDetach((void **)&actual_sendto, my_sendto);
	DetourDetach((void **)&actual_bind, my_bind);
	DetourDetach((void **)&actual_closesocket, my_closesocket);
	DetourTransactionCommit();

	DEBUG_LOG("unload_end")
	fclose(debug);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		load();
	} else if (dwReason == DLL_PROCESS_DETACH) {
		unload();
	}
	return TRUE;
}
