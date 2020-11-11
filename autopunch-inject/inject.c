#pragma ide diagnostic ignored "hicpp-signed-bitwise"
#include <windows.h>
#include <winsock2.h>
#include <detours.h>
#include <shlobj.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ws2tcpip.h>

#ifndef NDEBUG
#define DEBUG 1
#define DEBUG_LOG(fmt, ...) \
	fprintf(debug, "%s@%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
	fflush(debug);
#define DEBUG_ADDR(fmt, sockaddr, ...) \
	fprintf(debug, "%s@%d: " fmt "%d.%d.%d.%d:%d\n", __func__, __LINE__, ##__VA_ARGS__, (sockaddr)->sin_addr.S_un.S_un_b.s_b1, \
		(sockaddr)->sin_addr.S_un.S_un_b.s_b2, (sockaddr)->sin_addr.S_un.S_un_b.s_b3, (sockaddr)->sin_addr.S_un.S_un_b.s_b4, ntohs((sockaddr)->sin_port)); \
	fflush(debug);
#else
#define DEBUG 0
#define DEBUG_LOG(fmt, ...) ;
#define DEBUG_ADDR(fmt, addr, ...) ;
#endif

#define WARN(fmt, ...) \
	{ \
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
	if (r != 0) {
		DEBUG_LOG("getaddrinfow failed: %lu", r)
		return 0;
	}
	for (ADDRINFOW *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		if (ptr->ai_family == AF_INET) {
			u_long address = ((struct sockaddr_in *)ptr->ai_addr)->sin_addr.s_addr;
			DEBUG_ADDR("getaddrinfow success: ", ((struct sockaddr_in *)ptr->ai_addr))
			FreeAddrInfoW(result);
			return address;
		}
	}
	FreeAddrInfoW(result);
	DEBUG_LOG("getaddrinfow no dns results")
	return 0;
}

struct socket_data *get_socket_data(SOCKET s) {
	struct socket_data *socket_data = NULL;
	WaitForSingleObject(sockets_mutex, INFINITE);
	for (int i = 0; i < sockets_len; ++i) {
		if (sockets[i].s == s) {
			socket_data = &sockets[i];
			break;
		}
	}
	ReleaseMutex(sockets_mutex);
	return socket_data;
}

DWORD WINAPI relay(void *data) {
	while (true) {
		WaitForSingleObject(sockets_mutex, INFINITE);
		if (relay_close) {
			ReleaseMutex(sockets_mutex);
			return 0;
		}
		clock_t now = clock();
		if (relay_addr.sin_addr.s_addr == 0) {
			relay_addr.sin_addr.s_addr = get_relay_ip();
		}
		for (int i = 0; i < sockets_len; ++i) {
			struct socket_data *socket_data = &sockets[i];
			WaitForSingleObject(socket_data->mutex, INFINITE);
			if (socket_data->closed) {
				DEBUG_LOG("removing closed socket: socket=%zu closed=%d mappings=%zu mappings_len=%zu mappings_cap=%zu sockets_len=%zu sockets_cap=%zu", socket_data->s,
					socket_data->closed, (size_t)socket_data->mappings, socket_data->mappings_len, socket_data->mappings_cap, sockets_len, sockets_cap)
				ReleaseMutex(socket_data->mutex);
				CloseHandle(socket_data->mutex);
				free(socket_data->mappings);
				free(socket_data->transient_peers);
				sockets[i--] = sockets[--sockets_len];
				continue;
			}
			char buf[] = {((char *)&(socket_data->port))[0], ((char *)&(socket_data->port))[1]};
			DEBUG_LOG("sending to relay bound socket: socket=%zu socket_i=%d local_port=%u", socket_data->s, i, ntohs(socket_data->port))
			actual_sendto(socket_data->s, buf, sizeof(buf), 0, (struct sockaddr *)&relay_addr, sizeof(relay_addr));
			for (int j = 0; j < socket_data->mappings_len; ++j) {
				struct mapping *mapping = &socket_data->mappings[j];
				DEBUG_LOG("mapping process: socket=%zu socket_i=%d mapping_j=%d", socket_data->s, i, j)
				clock_t wait_refresh = (now - mapping->last_refresh) / CLOCKS_PER_SEC;
				if (wait_refresh > 10) { // drop old mapping
					DEBUG_LOG("mapping timeout: socket=%zu socket_i=%d mapping_j=%d wait_refresh=%ld", socket_data->s, i, j, wait_refresh)
					socket_data->mappings[j--] = socket_data->mappings[--socket_data->mappings_len];
					continue;
				}
				clock_t wait_send = (now - mapping->last_send) / CLOCKS_PER_SEC;
				if (mapping->refresh && (mapping->last_send == 0 || wait_send >= 1)) { // refresh mapping
					DEBUG_LOG("mapping refresh, send payload: socket=%zu socket_i=%d mapping_j=%d wait_send=%ld", socket_data->s, i, j, wait_send)
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
}

int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from_original, int *fromlen) {
	struct sockaddr_in *from = (struct sockaddr_in *)from_original;
	struct socket_data *socket_data = get_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("ignoring unknown socket: socket=%zu", s)
		return actual_recvfrom(s, out_buf, len, flags, from_original, fromlen); // TODO error?
	}

	char buf_backing[8];
	char *buf;
	if (len < 8) {
		buf = buf_backing;
	} else {
		buf = out_buf;
	}
	DEBUG_LOG("starting receive: socket=%zu len=%d flags=%d", s, len, flags)
	while (true) {
		int n = actual_recvfrom(s, buf, len > 8 ? len : 8, flags, from_original, fromlen);
		if (n < 0) {
			int err = WSAGetLastError();
			if (err == WSAECONNRESET) { // ignore connection reset errors (can happen if relay is down)
				DEBUG_LOG("recvfrom returned WSAECONNRESET, skipping")
				continue;
			}
			DEBUG_LOG("recvfrom returned error: err=%d", err)
			return err;
		}
		DEBUG_ADDR("recvfrom success: n=%d from=", from, n)
		if (from->sin_addr.s_addr == relay_addr.sin_addr.s_addr && from->sin_port == relay_addr.sin_port) {
			if (n != 8) {
				DEBUG_LOG("received invalid relay payload: invalid size n=%d", n)
				continue;
			}
			WaitForSingleObject(socket_data->mutex, INFINITE);
			clock_t now = clock();
			u_short port_internal = *((u_short *)(&buf[0]));
			u_short port_nat = *((u_short *)(&buf[2]));
			u_long addr = *(u_long *)(&buf[4]);
			DEBUG_LOG("received mapping from relay: socket=%zu internal_port=%d nat_port=%d", s, ntohs(port_internal), ntohs(port_nat))
			for (int j = 0; j < socket_data->mappings_len; ++j) {
				struct mapping *mapping = &socket_data->mappings[j];
				if (mapping->addr.sin_addr.s_addr != addr) {
					continue;
				}
				if (mapping->port != port_internal) {
					continue;
				}
				DEBUG_ADDR("updating mapping port: socket=%zu new_nat_port=%d internal_port=%d for ", &mapping->addr, s, ntohs(port_nat), ntohs(port_internal))
				mapping->addr.sin_port = port_nat;
				mapping->last_refresh = now;
				mapping->last_send = 0;
				goto outer;
			}
			if (socket_data->mappings_len == socket_data->mappings_cap) {
				socket_data->mappings_cap = socket_data->mappings_cap ? socket_data->mappings_cap * 2 : 8;
				socket_data->mappings = realloc(socket_data->mappings, socket_data->mappings_cap * sizeof(socket_data->mappings[0]));
			}
			socket_data->mappings[socket_data->mappings_len++] = (struct mapping) {
				.addr = (struct sockaddr_in) {
					.sin_family = AF_INET,
					.sin_port = port_nat,
					.sin_addr.s_addr = addr,
				},
				.port = port_internal,
				.last_refresh = now,
				.last_send = 0,
				.refresh = true,
			};
			DEBUG_ADDR("adding mapping: socket=%zu mappings_len=%zu mappings_cap=%zu internal_port=%d for ",
				&socket_data->mappings[socket_data->mappings_len - 1].addr, s, socket_data->mappings_len, socket_data->mappings_cap, ntohs(port_internal))
		outer:;
			ReleaseMutex(socket_data->mutex);
			continue;
		}

		WaitForSingleObject(socket_data->mutex, INFINITE);
		for (int i = 0; i < socket_data->transient_peers_len; ++i) {
			struct transient_peer *peer = &socket_data->transient_peers[i];
			if (peer->addr.sin_addr.s_addr != from->sin_addr.s_addr) {
				continue;
			}
			if (peer->addr.sin_port != from->sin_port) {
				DEBUG_ADDR("transient port mismatch: received_from=%d for ", &peer->addr, ntohs(from->sin_port))
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
					.sin_port = from->sin_port,
					.sin_addr.s_addr = from->sin_addr.s_addr,
				},
				.port = from->sin_port,
				.last_refresh = now,
				.last_send = now,
				.refresh = false,
			};
			DEBUG_ADDR("received transient, adding as mapping: socket=%zu mappings_len=%zu mappings_cap=%zu for ", from, s, socket_data->mappings_len,
				socket_data->mappings_cap)
			break;
		}

		if (n == sizeof(punch_payload) && !memcmp(punch_payload, buf, n)) {
			DEBUG_LOG("skipping punch payload")
			ReleaseMutex(socket_data->mutex);
			continue;
		}

		for (int i = 0; i < socket_data->mappings_len; ++i) {
			struct mapping *mapping = &socket_data->mappings[i];
			if (mapping->addr.sin_addr.s_addr != from->sin_addr.s_addr) {
				continue;
			}
			if (mapping->addr.sin_port != from->sin_port) {
				DEBUG_ADDR("mapping port mismatch: received_from=%d for ", &mapping->addr, ntohs(from->sin_port))
				continue;
			}
			DEBUG_ADDR("matched mapping, injecting internal_port=%d for ", from, ntohs(mapping->port))
			from->sin_port = mapping->port;
			break;
		}
		ReleaseMutex(socket_data->mutex);

		DEBUG_ADDR("received data: n=%d buf[0]=%d from ", from, n, buf[0])
		if (out_buf != buf) {
			memcpy(out_buf, buf, n);
		}
		return n;
	}
}

int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to_original, int tolen) {
	if (to_original->sa_family != AF_INET) {
		DEBUG_LOG("ignoring sendto with ignored family: socket=%zu family=%d", s, to_original->sa_family)
		return actual_sendto(s, buf, len, flags, to_original, tolen);
	}
	struct socket_data *socket_data = get_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("ignoring unknown socket: socket=%zu", s)
		return actual_sendto(s, buf, len, flags, to_original, tolen); // TODO error?
	}
	struct sockaddr_in *to = (struct sockaddr_in *)to_original;
	if (len) {
		DEBUG_ADDR("starting send: socket=%zu len=%d flags=%d buf[0]=%d to ", to, s, len, flags, buf[0])
	} else {
		DEBUG_ADDR("starting send (empty): socket=%zu flags=%d to ", to, s, flags)
	}
	WaitForSingleObject(socket_data->mutex, INFINITE);
	for (int i = 0; i < socket_data->mappings_len; ++i) {
		struct mapping *mapping = &socket_data->mappings[i];
		if (mapping->addr.sin_addr.s_addr != to->sin_addr.s_addr) {
			continue;
		}
		if (mapping->port != to->sin_port) {
			DEBUG_ADDR("mapping port mismatch: mapping_internal_port=%d for ", to, ntohs(mapping->port))
			continue;
		}
		clock_t now = clock();
		mapping->last_refresh = now;
		mapping->last_send = now;
		DEBUG_ADDR("matched mapping, injecting nat_port=%d for ", to, ntohs(mapping->addr.sin_port))
		int r = actual_sendto(s, buf, len, flags, (struct sockaddr *)mapping, tolen);
		ReleaseMutex(socket_data->mutex);
		return r;
	}
	int r = actual_sendto(s, buf, len, flags, to_original, tolen);

	int refresh = -1;
	clock_t now = clock();
	for (int i = 0; i < socket_data->transient_peers_len; ++i) {
		struct transient_peer *peer = &socket_data->transient_peers[i];
		if ((now - peer->last) / CLOCKS_PER_SEC > 10) { // transient peer timeout
			socket_data->transient_peers[i--] = socket_data->transient_peers[--socket_data->transient_peers_len];
			continue;
		}
		if (peer->addr.sin_addr.s_addr != to->sin_addr.s_addr) {
			continue;
		}
		if (peer->addr.sin_port != to->sin_port) {
			DEBUG_ADDR("transient port mismatch: send_to=%d for ", &peer->addr, ntohs(to->sin_port))
			continue;
		}
		refresh = (now - peer->last) * 1000 / CLOCKS_PER_SEC > 500;
		if (refresh) {
			peer->last = now;
		}
		DEBUG_ADDR("transient found: refresh=%d now=%ld last=%ld for ", to, refresh, now, peer->last)
		break;
	}
	if (refresh == -1) {
		if (socket_data->transient_peers_len == socket_data->transient_peers_cap) {
			socket_data->transient_peers_cap = socket_data->transient_peers_cap ? socket_data->transient_peers_cap * 2 : 8;
			socket_data->transient_peers = realloc(socket_data->transient_peers, socket_data->transient_peers_cap * sizeof(socket_data->transient_peers[0]));
		}
		socket_data->transient_peers[socket_data->transient_peers_len++] = (struct transient_peer) {
			.addr = (struct sockaddr_in) {
				.sin_family = AF_INET,
				.sin_port = to->sin_port,
				.sin_addr.s_addr = to->sin_addr.s_addr,
			},
			.last = now,
		};
		refresh = true;
		DEBUG_ADDR("adding transient: len=%zu cap=%zu for ", to, socket_data->transient_peers_len, socket_data->transient_peers_cap)
	}

	if (refresh) {
		char relay_buf[] = {((char *)&(socket_data->port))[0], ((char *)&(socket_data->port))[1], to->sin_addr.S_un.S_un_b.s_b1, to->sin_addr.S_un.S_un_b.s_b2,
			to->sin_addr.S_un.S_un_b.s_b3, to->sin_addr.S_un.S_un_b.s_b4, ((char *)&(to->sin_port))[0], ((char *)&(to->sin_port))[1]};
		actual_sendto(s, relay_buf, sizeof(relay_buf), 0, (struct sockaddr *)&relay_addr, sizeof(relay_addr));
		DEBUG_ADDR("refreshing transient, send payload: socket=%zu len=%zu cap=%zu for ", to, socket_data->s, socket_data->transient_peers_len,
			socket_data->transient_peers_cap)
	}
	ReleaseMutex(socket_data->mutex);
	return r;
}

int WINAPI my_bind(SOCKET s, const struct sockaddr *name, int namelen) {
	if (name) {
		DEBUG_ADDR("starting bind: socket=%zu for ", (const struct sockaddr_in *)name, s)
	} else {
		DEBUG_LOG("starting bind: socket=%zu without address", s)
	}
	int r = actual_bind(s, name, namelen);
	if (r) {
		DEBUG_LOG("bind failed: r=%d", r)
		return r;
	}
	struct sockaddr_in local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	if (getsockname(s, (struct sockaddr *)&local_addr, &local_addr_len)) {
		DEBUG_LOG("getsockname failed: err=%d", WSAGetLastError())
		return r;
	}
	if (local_addr.sin_family != AF_INET) {
		DEBUG_LOG("ignoring socket with ignored family: family=%d", local_addr.sin_family)
		return r;
	}
	DEBUG_LOG("bound local port: socket=%zu local_port=%d", s, ntohs(local_addr.sin_port))
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
	DEBUG_LOG("adding socket: socket=%zu local_port=%d", s, ntohs(local_addr.sin_port))
	ReleaseMutex(sockets_mutex);
	return r;
}

int WINAPI my_closesocket(SOCKET s) {
	struct socket_data *socket_data = get_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("ignoring unknown socket: socket=%zu", s)
		return actual_closesocket(s);
	}
	DEBUG_LOG("starting close: socket=%zu", s)
	int r = actual_closesocket(s);
	if (r) {
		DEBUG_LOG("close failed: err=%d", WSAGetLastError())
	}
	WaitForSingleObject(socket_data->mutex, INFINITE);
	socket_data->closed = true;
	ReleaseMutex(socket_data->mutex);
	return r;
}

void load() {
	if (DEBUG) {
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
	DEBUG_LOG("unload free sockets: %zu %zu %zu", sockets_len, sockets_cap, (size_t)sockets)
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
