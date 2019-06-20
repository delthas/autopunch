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

// TODO multiple relays
const int relay_ip = (188 << 24) | (226 << 16) | (135 << 8) | 111;
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

struct pending_iocp {
		SOCKET socket;
		HANDLE iocp;
		ULONG_PTR key;
};
struct pending_iocp *pending_iocps;
size_t pending_iocps_len;
size_t pending_iocps_cap;

struct iocp_key {
		HANDLE iocp;
		SOCKET socket;
		ULONG_PTR key;
};

#define OVERLAPPED_TYPE_RECV 0xBC
#define OVERLAPPED_TYPE_SEND 0xCB

struct iocp_overlapped {
		WSAOVERLAPPED _;
		unsigned char type;
};

struct iocp_overlapped_recv {
		struct iocp_overlapped type;
		LPWSABUF buffers;
		DWORD buffers_count;
		LPDWORD bytes_sent;
		LPDWORD flags;
		struct sockaddr *from;
		int *fromlen;
		LPWSAOVERLAPPED overlapped;
		LPWSAOVERLAPPED_COMPLETION_ROUTINE routine;
		char buf_data[8];
		bool buf_data_used;
};

struct iocp_overlapped_send {
		struct iocp_overlapped type;
		LPWSAOVERLAPPED overlapped;
};

HANDLE iocp;
HANDLE receive_thread;

bool close;

int(WINAPI *actual_recvfrom)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) = recvfrom;
int(WINAPI *actual_sendto)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) = sendto;
int(WINAPI *actual_bind)(SOCKET s, const struct sockaddr *name, int namelen) = bind;
int(WINAPI *actual_closesocket)(SOCKET s) = closesocket;
int(WINAPI *actual_WSARecvFrom)(SOCKET s, LPWSABUF buffers, DWORD buffers_count, LPDWORD bytes_sent, LPDWORD flags, struct sockaddr *from, int *fromlen, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) = WSARecvFrom;
int(WINAPI *actual_WSASendTo)(SOCKET s, LPWSABUF buffers, DWORD buffers_count, LPDWORD bytes_sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED overlapped, 	LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) = WSASendTo;
HANDLE(WINAPI *actual_CreateIoCompletionPort)(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads) = CreateIoCompletionPort;

DWORD WINAPI relay(void *data) {
	while (!close) {
		WaitForSingleObject(sockets_mutex, INFINITE);
		clock_t now = clock();
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
		if (close) {
			return 0;
		}
		Sleep(500);
	}
	return 0;
}

struct socket_data *find_socket_data(SOCKET s) {
	struct socket_data *socket_data = NULL;
	WaitForSingleObject(sockets_mutex, INFINITE);
	for (int i = 0; i < sockets_len; ++i) {
		socket_data = &sockets[i];
		if (socket_data->s == s) {
			break;
		}
	}
	ReleaseMutex(sockets_mutex);
	return socket_data;
}

void associate_iocp(SOCKET s) {
	for (int i = 0; i < pending_iocps_len; ++i) {
		struct pending_iocp *pending_iocp = &pending_iocps[i];
		if (pending_iocp->socket != s) {
			continue;
		}
		// TODO check err
		actual_CreateIoCompletionPort((HANDLE) pending_iocp->socket, pending_iocp->iocp, pending_iocp->key, 0);
		pending_iocps[i--] = pending_iocps[--pending_iocps_len];
	}
}

bool inject_receive(struct socket_data *socket_data, struct sockaddr_in *addr, int n, const char *buf) { // true means to forward the packet, false to continue
	if (addr->sin_addr.s_addr == relay_addr.sin_addr.s_addr && addr->sin_port == relay_addr.sin_port) {
		if (n % 8) {
			DEBUG_LOG("recvfrom error receive size n=%d", n)
			return false;
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
		return false;
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
		return false;
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
	return true;
}

// TODO createiocp if needed (add in all funs) WSASendMsg WSASendTo WSASend WSARecvFrom WSARecvMsg WSARecv

int WINAPI my_WSARecvFrom(SOCKET s, LPWSABUF out_buffers, DWORD out_buffers_count, LPDWORD bytes_sent, LPDWORD flags, struct sockaddr *from, int *fromlen, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
	struct sockaddr_in *addr = (struct sockaddr_in *)from;
	struct socket_data *socket_data = find_socket_data(s);
	if (!socket_data) {
		associate_iocp(s);
		DEBUG_LOG("wsarecvfrom error unknown socket")
		return actual_WSARecvFrom(s, out_buffers, out_buffers_count, bytes_sent, flags, from, fromlen, overlapped, completion_routine); // TODO error handling
	}

	int len = 0;
	for (int i = 0; i < out_buffers_count; ++i) {
		len += out_buffers[i].len;
	}
	if(out_buffers_count > 0 && out_buffers[0].len > 0) {
		DEBUG_LOG("WSAsendto start socket=%zu len=%d buf[0]=%d", s, len, out_buffers[0].buf[0])
	} else {
		DEBUG_LOG("WSAsendto start socket=%zu len=%d (empty)", s, len)
	}

	if(overlapped == NULL && completion_routine == NULL) {
		char buf_data[8];
		LPWSABUF buffers;
		DWORD buffers_count;
		if(out_buffers_count == 0 || out_buffers[0].len < 8) {
			struct _WSABUF relay_bufs = {
							.len = sizeof(buf_data),
							.buf = buf_data,
			};
			buffers = &relay_bufs;
			buffers_count = 1;
		} else {
			buffers = out_buffers;
			buffers_count = out_buffers_count;
		}

		DEBUG_LOG("wsarecvfrom_start len=%d flags=%d", len, flags)
		while (true) {
			int n = actual_WSARecvFrom(s, buffers, buffers_count, bytes_sent, flags, from, fromlen, NULL, NULL);
			DEBUG_LOG("wsarecvfrom actual n=%d", n)
			if (n < 0) {
				int err = WSAGetLastError();
				if (err == WSAECONNRESET) { // ignore connection reset errors (can happen if relay is down)
					DEBUG_LOG("wsarecvfrom skipped error=%d", err)
					continue;
				}
				DEBUG_LOG("wsarecvfrom error=%d", err)
				return n;
			}

			if(!inject_receive(socket_data, addr, n, buffers[0].buf)) {
				continue;
			}
			if(out_buffers != buffers) {
				int r = 0;
				for (int i = 0; i < out_buffers_count && r < n; ++i) {
					if(buffers[i].len >= n - r) {
						memcpy(out_buffers[i].buf, &buf_data[r], n - r);
						break;
					} else {
						memcpy(out_buffers[i].buf, &buf_data[r], out_buffers[i].len);
						r += out_buffers[i].len;
					}
				}
			}
			return n;
		}
	}

	struct iocp_overlapped_recv *inject_overlapped = calloc(1, sizeof(*inject_overlapped));
	inject_overlapped->type.type = OVERLAPPED_TYPE_RECV;
	inject_overlapped->buffers = out_buffers;
	inject_overlapped->buffers_count = out_buffers_count;
	inject_overlapped->bytes_sent = bytes_sent;
	inject_overlapped->flags = flags;
	inject_overlapped->from = from;
	inject_overlapped->fromlen = fromlen;
	inject_overlapped->overlapped = overlapped;
	inject_overlapped->routine = completion_routine;

	LPWSABUF buffers;
	DWORD buffers_count;
	if(out_buffers_count == 0 || out_buffers[0].len < 8) {
		struct _WSABUF relay_bufs = {
						.len = sizeof(inject_overlapped->buf_data),
						.buf = inject_overlapped->buf_data,
		};
		buffers = &relay_bufs;
		buffers_count = 1;
		inject_overlapped->buf_data_used = true;
	} else {
		buffers = out_buffers;
		buffers_count = out_buffers_count;
		inject_overlapped->buf_data_used = false;
	}

	int r = actual_WSARecvFrom(s, buffers, buffers_count, bytes_sent, flags, from, fromlen, (LPWSAOVERLAPPED)inject_overlapped, NULL);
	if(!r) {
		r = SOCKET_ERROR;
		WSASetLastError(WSA_IO_PENDING);
	}
	// TODO return data immediately if not relay?
	return r;
}

int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from, int *fromlen) {
	struct sockaddr_in *addr = (struct sockaddr_in *)from;
	struct socket_data *socket_data = find_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("recvfrom error unknown socket")
		return actual_recvfrom(s, out_buf, len, flags, from, fromlen); // TODO error handling
	}
	
	char buf_data[8];
	char *buf;
	if(len < 8) {
		buf = buf_data;
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
			return n;
		}

		if(!inject_receive(socket_data, addr, n, buf)) {
			continue;
		}
		if(out_buf != buf) {
			memcpy(out_buf, buf, n);
		}
		return n;
	}
}

bool find_mapping(struct socket_data *socket_data, const struct sockaddr_in **dest) {
	for (int i = 0; i < socket_data->mappings_len; ++i) {
		struct mapping *mapping = &socket_data->mappings[i];
		if (mapping->addr.sin_addr.s_addr != (*dest)->sin_addr.s_addr) {
			continue;
		}
		if (mapping->port != (*dest)->sin_port) {
			DEBUG_LOG("sendto mapping port mismatch mapping=%d dest=%d", ntohs(mapping->port), ntohs((*dest)->sin_port))
			continue;
		}
		clock_t now = clock();
		mapping->last_refresh = now;
		mapping->last_send = now;
		DEBUG_LOG("sendto mapping used old=%d replaced=%d", ntohs((*dest)->sin_port), ntohs(mapping->addr.sin_port))
		*dest = &mapping->addr;
		return true;
	}
	DEBUG_LOG("WSAsendto unknown mapping for port=%d sending to peer and relay", ntohs((*dest)->sin_port))
	return false;
}

void refresh_transient(SOCKET s, struct socket_data *socket_data, const struct sockaddr_in *dest) {
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
}

int WINAPI my_WSASendTo(SOCKET s, LPWSABUF buffers, DWORD buffers_count, LPDWORD bytes_sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED overlapped, 	LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
	int len = 0;
	for (int i = 0; i < buffers_count; ++i) {
		len += buffers[i].len;
	}
	if(buffers_count > 0 && buffers[0].len > 0) {
		DEBUG_LOG("WSAsendto start socket=%zu len=%d buf[0]=%d", s, len, buffers[0].buf[0])
	} else {
		DEBUG_LOG("WSAsendto start socket=%zu len=%d (empty)", s, len)
	}
	struct socket_data *socket_data = find_socket_data(s);
	if (!socket_data) {
		associate_iocp(s);
		DEBUG_LOG("WSAsendto error unknown socket")
		return actual_WSASendTo(s, buffers, buffers_count, bytes_sent, flags, to, tolen, overlapped, completion_routine); // TODO error?
	}
	if (to->sa_family != AF_INET) {
		// TODO trigger iocp (wrap overlap in inject overlapped)
		struct iocp_overlapped_send *overlapped_send = calloc(1, sizeof(*overlapped_send));
		overlapped_send->type.type = OVERLAPPED_TYPE_SEND;
		overlapped_send->overlapped = overlapped;
		DEBUG_LOG("WSAsendto mapping sa_family != AF_INET: %d", to->sa_family)
		return actual_WSASendTo(s, buffers, buffers_count, bytes_sent, flags, to, tolen, (LPWSAOVERLAPPED)overlapped_send, completion_routine);
	}

	WaitForSingleObject(socket_data->mutex, INFINITE);
	const struct sockaddr_in *dest = (const struct sockaddr_in *)to;
	bool found = find_mapping(socket_data, &dest);

	struct iocp_overlapped_send *overlapped_send = calloc(1, sizeof(*overlapped_send));
	overlapped_send->type.type = OVERLAPPED_TYPE_SEND;
	overlapped_send->overlapped = overlapped;
	int r = actual_WSASendTo(s, buffers, buffers_count, bytes_sent, flags, (struct sockaddr *)dest, tolen, overlapped, completion_routine);

	if(!found) {
		int err = WSAGetLastError();
		refresh_transient(s, socket_data, dest);
		WSASetLastError(err);
	}

	ReleaseMutex(socket_data->mutex);
	return r;
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
	struct socket_data *socket_data = find_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("sendto error unknown socket")
		return actual_sendto(s, buf, len, flags, to, tolen); // TODO error?
	}

	WaitForSingleObject(socket_data->mutex, INFINITE);
	const struct sockaddr_in *dest = (const struct sockaddr_in *)to;
	bool found = find_mapping(socket_data, &dest);

	int r = actual_sendto(s, buf, len, flags, to, tolen);

	if(!found) {
		int err = WSAGetLastError();
		refresh_transient(s, socket_data, dest);
		WSASetLastError(err);
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
	int socket_type;
	int socket_type_length = sizeof(socket_type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&socket_type, &socket_type_length)) {
		DEBUG_LOG("bind getsockopt error %d", WSAGetLastError())
		return r;
	}
	if (socket_type != SOCK_DGRAM) {
		DEBUG_LOG("bind ignoring non-datagram socket %d", socket_type)
		return r;
	}
	struct sockaddr_in local_addr;
	socklen_t local_addr_len = sizeof(local_addr);
	if (getsockname(s, (struct sockaddr *)&local_addr, &local_addr_len)) {
		DEBUG_LOG("bind getsockname error %d", WSAGetLastError())
		return r;
	}
	if (local_addr.sin_family != AF_INET) {
		associate_iocp(s);
		DEBUG_LOG("bind ignoring non-AF_INET socket %d", local_addr.sin_family)
		return r;
	}
	DEBUG_LOG("bind local port is %d %d", local_addr.sin_family, ntohs(local_addr.sin_port))

	for (int i = 0; i < pending_iocps_len; ++i) {
		struct pending_iocp *pending_iocp = &pending_iocps[i];
		if (pending_iocp->socket != s) {
			continue;
		}
		// TODO check err
		// TODO free iocp_key
		struct iocp_key *key = malloc(sizeof(*key));
		key->socket = s;
		key->iocp = pending_iocp->iocp;
		key->key = pending_iocp->key;
		actual_CreateIoCompletionPort((HANDLE) pending_iocp->socket, iocp, (ULONG_PTR)key, 0);
		pending_iocps[i--] = pending_iocps[--pending_iocps_len];
	}

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

int WINAPI my_closesocket(SOCKET s) {
	DEBUG_LOG("close start socket=%zu", s)
	int r = actual_closesocket(s);
	if (r) {
		DEBUG_LOG("close error=%d", WSAGetLastError())
	}
	struct socket_data *socket_data = find_socket_data(s);
	if (!socket_data) {
		DEBUG_LOG("close error unknown socket, err=%d", r)
		return r;
	}
	// TODO free iocp key
	WaitForSingleObject(socket_data->mutex, INFINITE);
	socket_data->closed = true;
	ReleaseMutex(socket_data->mutex);
	DEBUG_LOG("close end")
	return r;
}

HANDLE WINAPI my_CreateIoCompletionPort(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads) {
	if(ExistingCompletionPort == NULL) {
		return actual_CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
	}
	int type = -1;
	int length = sizeof(type);
	getsockopt((SOCKET)FileHandle, SOL_SOCKET, SO_TYPE, (char *)&type, &length);
	if(type != SOCK_DGRAM) {
		return actual_CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
	}
	if (pending_iocps_len == pending_iocps_cap) {
		pending_iocps_cap = pending_iocps_cap ? pending_iocps_cap * 2 : 8;
		pending_iocps = realloc(pending_iocps, pending_iocps_cap * sizeof(pending_iocps[0]));
	}
	pending_iocps[pending_iocps_len++] = (struct pending_iocp){
					.socket = (SOCKET)FileHandle,
					.iocp = ExistingCompletionPort,
					.key = CompletionKey,
	};
	return iocp;
}

DWORD WINAPI receive(void *data) {
	while (!close) {
		DWORD n;
		struct iocp_key *key;
		struct iocp_overlapped *overlapped_;
		int err = 0;
		int r = GetQueuedCompletionStatus(iocp, &n, (PULONG_PTR) &key, (LPOVERLAPPED *) &overlapped_, INFINITE);
		if(!r && !overlapped_) {
			DEBUG_LOG("GetQueuedCompletionStatus overlapped=null error=%d", WSAGetLastError())
			continue;
		} else if(!r) {
			err = GetLastError(); // not WSAGetLastError
		}
		if(overlapped_->type == OVERLAPPED_TYPE_SEND) {
			struct iocp_overlapped_send *overlapped = (struct iocp_overlapped_send *)overlapped_;
			PostQueuedCompletionStatus(key->iocp, n, key->key, overlapped->overlapped);
			free(overlapped);
		} else if(overlapped_->type == OVERLAPPED_TYPE_RECV) {
			struct iocp_overlapped_recv *overlapped = (struct iocp_overlapped_recv *)overlapped_;
			struct sockaddr_in *addr = (struct sockaddr_in *) overlapped->from;

			// TODO what to do if n < 0?
			// TODO get socket data!
			// TODO socket mutexes

			if(!inject_receive(socket_data, addr, n, overlapped->buffers[0].buf)) {
				actual_WSARecvFrom(key->socket, overlapped->buffers, overlapped->buffers_count, overlapped->bytes_sent, overlapped->flags, overlapped->from, overlapped->fromlen, (LPWSAOVERLAPPED) overlapped, NULL);
			} else {
				if(overlapped->buf_data_used) {
					int r = 0;
					for (int i = 0; i < overlapped->buffers_count && r < n; ++i) {
						if(overlapped->buffers[i].len >= n - r) {
							memcpy(overlapped->buffers[i].buf, &overlapped->buf_data[r], n - r);
							break;
						} else {
							memcpy(overlapped->buffers[i].buf, &overlapped->buf_data[r], overlapped->buffers[i].len);
							r += overlapped->buffers[i].len;
						}
					}
				}

				PostQueuedCompletionStatus(key->iocp, n, key->key, overlapped->overlapped);
				if(overlapped->routine == NULL) {
					if(overlapped->overlapped->hEvent != NULL) {
						WSASetEvent(overlapped->overlapped->hEvent);
					}
				} else {
					// TODO must be scheduled to be run in alertable state?
					overlapped->routine(err /* TODO */, n, overlapped->overlapped, *overlapped->flags);
				}
			}

			// TODO error checking

			free(overlapped);
		} else {
			DEBUG_LOG("GetQueuedCompletionStatus error unknown overlapped type: %d", overlapped_->type)
		}
	}
	return 0;
}

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
	DetourAttach((void **)&actual_WSARecvFrom, my_WSARecvFrom);
	DetourAttach((void **)&actual_WSASendTo, my_WSASendTo);
	DetourAttach((void **)&actual_CreateIoCompletionPort, my_CreateIoCompletionPort);
	DetourTransactionCommit();

	u_long relay_ip_net = htonl(relay_ip);
	u_short relay_port_net = htons(relay_port);
	relay_addr = (struct sockaddr_in){.sin_family = AF_INET, .sin_port = relay_port_net, .sin_addr.s_addr = relay_ip_net};

	iocp = actual_CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	sockets_mutex = CreateMutex(NULL, FALSE, NULL);
	relay_thread = CreateThread(NULL, 0, relay, NULL, 0, NULL);
	receive_thread = CreateThread(NULL, 0, receive, NULL, 0, NULL);

	DEBUG_LOG("load_end")
}

void unload() {
	DEBUG_LOG("unload_start")

	close = true;
	WaitForSingleObject(sockets_mutex, INFINITE);
	CloseHandle(relay_thread);
	CloseHandle(receive_thread); // TODO is this the right place?
	ReleaseMutex(sockets_mutex);
	CloseHandle(sockets_mutex);
	CloseHandle(iocp);
	DEBUG_LOG("unload_free %zu %zu %zu", sockets_len, sockets_cap, (size_t)sockets)
	free(sockets);
	
	DEBUG_LOG("unload_detours")
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((void **)&actual_recvfrom, my_recvfrom);
	DetourDetach((void **)&actual_sendto, my_sendto);
	DetourDetach((void **)&actual_bind, my_bind);
	DetourDetach((void **)&actual_closesocket, my_closesocket);
	DetourDetach((void **)&actual_WSARecvFrom, my_WSARecvFrom);
	DetourDetach((void **)&actual_WSASendTo, my_WSASendTo);
	DetourDetach((void **)&actual_CreateIoCompletionPort, my_CreateIoCompletionPort);
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
