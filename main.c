#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <WS2tcpip.h>
#include <WinSock2.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUFFER_SIZE 256

#ifdef DEBUG
#define debug(fmt, ...)                                                        \
    do {                                                                       \
        if (DEBUG)                                                             \
            fprintf(stderr, fmt, __VA_ARGS__);                                 \
    } while (0)
#else
#define debug(fmt, ...) /* empty */
#endif

enum telnet_command {
    TELNET_COMMAND_SE = 240,
    TELNET_COMMAND_NOP = 241,
    TELNET_COMMAND_DATA_MARK = 242,
    TELNET_COMMAND_BREAK = 243,
    TELNET_COMMAND_INTERRUPT_PROCESS = 244,
    TELNET_COMMAND_ABORT_OUTPUT = 245,
    TELNET_COMMAND_ARE_YOU_THERE = 246,
    TELNET_COMMAND_ERASE_CHARACTER = 247,
    TELNET_COMMAND_ERASE_LINE = 248,
    TELNET_COMMAND_GO_AHEAD = 249,
    TELNET_COMMAND_SB = 250,

    TELNET_COMMAND_WILL = 251,
    TELNET_COMMAND_WONT = 252,
    TELNET_COMMAND_DO = 253,
    TELNET_COMMAND_DONT = 254,
    TELNET_COMMAND_IAC = 255,
};

enum telnet_option {
    TELNET_OPTION_BINARY = 0,
    TELNET_OPTION_ECHO = 1,
    TELNET_OPTION_SUPPRESS_GO_AHEAD = 3,
    TELNET_OPTION_STATUS = 5,
    TELNET_OPTION_TIMING_MARK = 6,
    TELNET_OPTION_LINE_WIDTH = 8,
    TELNET_OPTION_PAGE_SIZE = 9,
    TELNET_OPTION_TERMINAL_TYPE = 24,
    TELNET_OPTION_TERMINAL_SPEED = 32,
    TELNET_OPTION_LINE_MODE = 34
};

enum telnet_command_state {
    TELNET_COMMAND_STATE_IAC,
    TELNET_COMMAND_STATE_COMMAND,
    TELNET_COMMAND_STATE_PERMISSIVE,
    TELNET_COMMAND_STATE_SUBCOMMAND,
    TELNET_COMMAND_STATE_PENDING,
    TELNET_COMMAND_STATE_UNKNOWN
};

struct buffer {
    char buf[BUFFER_SIZE];
    rsize_t buf_size;
};

int buffer_write(struct buffer *b, char *msg, rsize_t msg_size) {
    msg_size = msg_size + b->buf_size > BUFFER_SIZE
                   ? msg_size - (BUFFER_SIZE - b->buf_size)
                   : msg_size;
    memmove(b->buf + b->buf_size, msg, msg_size);
    b->buf_size += msg_size;

    return msg_size;
}

struct network_virtual_terminal_settings {
    _Bool echo;
    _Bool line_mode;
    _Bool suppress_go_ahead;
};

struct network_virtual_terminal_settings NVT_DEFAULT_SETTINGS = {
    .echo = 0, .line_mode = 1, .suppress_go_ahead = 0};

struct network_virtual_terminal;

typedef void (*network_virtual_terminal_printer_fn)(
    struct network_virtual_terminal *, char *, int);

struct network_virtual_terminal {
    struct buffer printer;
    struct buffer keyboard;
    struct network_virtual_terminal_settings settings;
    enum telnet_command_state command_state;
    struct buffer command;

    SOCKET socket;
    _Bool stop;

    struct network_virtual_terminal *next;
};

struct telnet_server {
    SOCKET socket;
    WSADATA wsa_data;
    network_virtual_terminal_printer_fn printer_fn;

    struct network_virtual_terminal *nvts;
};

enum telnet_server_error {
    TELNET_SERVER_ERROR_OK = 0,
    TELNET_SERVER_ERROR_WSADATA = -1,
    TELNET_SERVER_ERROR_ADDRINFO = -2,
    TELNET_SERVER_ERROR_SOCKET = -3,
    TELNET_SERVER_ERROR_BIND = -4,
    TELNET_SERVER_ERROR_LISTEN = -5
};

enum telnet_server_error
init_telnet_server(struct telnet_server *ts, const char *host,
                   const char *service,
                   network_virtual_terminal_printer_fn printer_fn) {
    int result;
    struct addrinfo *addrinfo;
    struct addrinfo hints;

    memset(ts, 0, sizeof(struct telnet_server));
    ts->printer_fn = printer_fn;

    result = WSAStartup((MAKEWORD(2, 2)), &ts->wsa_data);

    if (result != 0) {
        return TELNET_SERVER_ERROR_WSADATA;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    result = getaddrinfo(host, service, &hints, &addrinfo);
    if (result != 0) {
        WSACleanup();
        return TELNET_SERVER_ERROR_ADDRINFO;
    }

    ts->socket = socket(addrinfo->ai_family, addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
    if (ts->socket == INVALID_SOCKET) {
        freeaddrinfo(addrinfo);
        WSACleanup();
        return TELNET_SERVER_ERROR_SOCKET;
    }

    result = bind(ts->socket, addrinfo->ai_addr, (int)addrinfo->ai_addrlen);
    if (result == SOCKET_ERROR) {
        freeaddrinfo(addrinfo);
        closesocket(ts->socket);
        WSACleanup();
        return TELNET_SERVER_ERROR_BIND;
    }

    freeaddrinfo(addrinfo);

    result = listen(ts->socket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        closesocket(ts->socket);
        WSACleanup();
        return TELNET_SERVER_ERROR_LISTEN;
    }

    return TELNET_SERVER_ERROR_OK;
}

void init_network_virtual_terminal(
    struct network_virtual_terminal *nvt,
    struct network_virtual_terminal_settings *nvt_settings) {

    memset(nvt, 0, sizeof(*nvt));

    if (!nvt_settings) {
        nvt->settings = NVT_DEFAULT_SETTINGS;
    } else {
        memcpy(&nvt->settings, nvt_settings, sizeof(*nvt_settings));
    }

    nvt->command_state = TELNET_COMMAND_STATE_PENDING;
}

int telnet_server_process_message(struct telnet_server *ts,
                                  struct network_virtual_terminal *nvt,
                                  char *msg, int nbytes, char *out_msg,
                                  int *out_nbytes) {
    unsigned char *umsg = (unsigned char *)msg;
    int i = 0;
    for (; i < nbytes; i++, umsg++) {
        if (*umsg == TELNET_COMMAND_IAC &&
            nvt->command_state == TELNET_COMMAND_STATE_PENDING) {
            nvt->command_state = TELNET_COMMAND_STATE_IAC;
            buffer_write(&nvt->command, msg + i, 1);
            debug("IAC START\n");
            continue;
        } else if (*umsg == TELNET_COMMAND_IAC &&
                   nvt->command_state != TELNET_COMMAND_STATE_PENDING) {
            debug("error: not in pending state, but recieved IAC.\n");
            return -1;
        }

        switch (*umsg) {
        case TELNET_COMMAND_WILL:
        case TELNET_COMMAND_WONT:
        case TELNET_COMMAND_DO:
        case TELNET_COMMAND_DONT:
            if (nvt->command_state != TELNET_COMMAND_STATE_IAC) {
                debug("error: should not be in any other state than IAC.\n");
                return -1;
            }
            debug("PERMISSIVE\n");

            nvt->command_state = TELNET_COMMAND_STATE_PERMISSIVE;
            buffer_write(&nvt->command, msg + i, 1);
            continue;
        }

        switch (nvt->command_state) {
        case TELNET_COMMAND_STATE_PERMISSIVE:
            switch (*umsg) {
            case TELNET_OPTION_BINARY:
            case TELNET_OPTION_ECHO:
            case TELNET_OPTION_SUPPRESS_GO_AHEAD:
            case TELNET_OPTION_STATUS:
            case TELNET_OPTION_TIMING_MARK:
            case TELNET_OPTION_LINE_WIDTH:
            case TELNET_OPTION_PAGE_SIZE:
            case TELNET_OPTION_TERMINAL_TYPE:
            case TELNET_OPTION_TERMINAL_SPEED:
            case TELNET_OPTION_LINE_MODE:
                buffer_write(&nvt->command, msg + i, 1);
                nvt->command_state = TELNET_COMMAND_STATE_PENDING;

                debug("VALID OPTION PASSED.\n");
                break;
            default:
                debug("INVALID OPTION PASSED.\n");
                return -1;
            }
            break;
        }
    }

    return nvt->command_state != TELNET_COMMAND_STATE_PENDING;
}

int telnet_server_handle_accept(struct telnet_server *ts) {
    struct network_virtual_terminal *nvt =
        malloc(sizeof(struct network_virtual_terminal));
    if (!nvt)
        return -1;

    init_network_virtual_terminal(nvt, NULL);

    nvt->next = ts->nvts;
    ts->nvts = nvt;

    int nbytes = buffer_write(
        &nvt->keyboard,
        (char[]){TELNET_COMMAND_IAC, TELNET_COMMAND_DO, TELNET_OPTION_ECHO}, 3);

    if (nbytes != 3) {
        debug("failed to write command to buffer.\n");
        return -1;
    }

    nvt->socket = accept(ts->socket, NULL, NULL);
    if (nvt->socket == INVALID_SOCKET) {
        closesocket(ts->socket);
        return -1;
    }

    return 0;
}

void telnet_server_serve_forever(struct telnet_server *ts) {
    fd_set readfds;
    fd_set writefds;
    int result;

    while (1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(ts->socket, &readfds);

        for (struct network_virtual_terminal *nvt = ts->nvts; nvt;
             nvt = nvt->next) {
            FD_SET(nvt->socket, &readfds);
            FD_SET(nvt->socket, &writefds);
        }

        result = select(0, &readfds, &writefds, NULL, NULL);
        if (result == SOCKET_ERROR) {
            debug("select failed with error %d.\n", WSAGetLastError());
            return;
        }

        if (FD_ISSET(ts->socket, &readfds)) {
            if (telnet_server_handle_accept(ts) != 0) {
                debug("telnet_server_handle_accept failed with error %d.\n",
                      WSAGetLastError());
                return;
            }
            debug("new connection made.\n");
        }

        for (struct network_virtual_terminal *nvt = ts->nvts; nvt;
             nvt = nvt->next) {
            if (FD_ISSET(nvt->socket, &readfds) &&
                nvt->printer.buf_size < BUFFER_SIZE) {
                debug("reading from fd.\n");
                int nbytes =
                    recv(nvt->socket, nvt->printer.buf + nvt->printer.buf_size,
                         BUFFER_SIZE - nvt->printer.buf_size, 0);
                if (nbytes > 0) {
                    nvt->printer.buf_size += nbytes;
                } else {
                    debug("connection closed\n");
                    nvt->stop = 1;
                }

                char *recv_start =
                    nvt->printer.buf + nvt->printer.buf_size - nbytes;

#ifdef DEBUG
                debug("< [ ");
                for (int i = 0; i < nbytes; i++) {
                    debug("%d ", (unsigned char)recv_start[i]);
                }
                debug("]\n");
#endif

                if (telnet_server_process_message(ts, nvt, recv_start,
                                                  nbytes) == 0)
                    ts->printer_fn(nvt, recv_start, nbytes);
            }
            if (FD_ISSET(nvt->socket, &writefds) &&
                nvt->keyboard.buf_size > 0) {
                debug("writing to fd.\n");

                int nbytes = send(nvt->socket, nvt->keyboard.buf,
                                  nvt->keyboard.buf_size, 0);
                if (nbytes == SOCKET_ERROR) {
                    debug("send failed with error %d.\n", WSAGetLastError());
                    return;
                }

#ifdef DEBUG
                debug("> [ ");
                for (int i = 0; i < nbytes; i++) {
                    debug("%d ", (unsigned char)nvt->keyboard.buf[i]);
                }
                debug("]\n");
#endif

                memmove(nvt->keyboard.buf, nvt->keyboard.buf + nbytes,
                        nvt->keyboard.buf_size - nbytes);
                nvt->keyboard.buf_size -= nbytes;
            }
        }

        struct network_virtual_terminal *tmp = ts->nvts, *prev = NULL;

        while (tmp != NULL) {
            if (tmp->stop) {
                if (prev == NULL) {
                    ts->nvts = tmp->next;
                    closesocket(tmp->socket);
                    free(tmp);
                    tmp = ts->nvts;
                } else {
                    prev->next = tmp->next;
                    closesocket(tmp->socket);
                    free(tmp);
                    tmp = prev->next->next;
                }
            } else {
                prev = tmp;
                tmp = tmp->next;
            }
        }
    }
}

void echo_printer_fn(struct network_virtual_terminal *nvt, char *msg,
                     int nbytes) {
    buffer_write(&nvt->keyboard, msg, nbytes);
    nvt->printer.buf_size -= nbytes;
}

int main(int argc, char **argv) {
    struct telnet_server ts;
    enum telnet_server_error tse =
        init_telnet_server(&ts, NULL, "5000", echo_printer_fn);
    if (tse != TELNET_SERVER_ERROR_OK) {
        fprintf(stderr, "init_telnet_server failed with error %d", tse);
        WSACleanup();
        return EXIT_FAILURE;
    }

    telnet_server_serve_forever(&ts);

    WSACleanup();

    return EXIT_SUCCESS;
}