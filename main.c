#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <netdb.h>

#include "sha1.h"
#include "b64.h"

#define BUFF_LEN 32768

#ifndef TCPT_CLIENT
#ifndef TCPT_SERVER
#define TCPT_SERVER // Default to TCPT_SERVER
#endif
#endif

uint64_t _htonll(uint64_t hostlonglong){
    uint32_t t = 1;
    if(htonl(t) == t)
        return hostlonglong;

    uint64_t ret;
#define upper32(x) *((uint32_t *)&(x) + 0)
#define lower32(x) *((uint32_t *)&(x) + 1)
    lower32(ret) = htonl(upper32(hostlonglong));
    upper32(ret) = htonl(lower32(hostlonglong));
#undef lower32
#undef upper32
    return ret;
}

typedef struct __attribute__((packed)){
    unsigned len:7;
    unsigned mask:1;
    //enum WS_FRAME_OPCODE opcode:4;
    unsigned opcode:4;
    unsigned rsv3:1;
    unsigned rsv2:1;
    unsigned rsv1:1;
    unsigned fin:1;
}WS_FRAME_HDR;


enum WS_FRAME_OPCODE{
    WS_FRAME_OPCODE_CONT  = 0x0,
    WS_FRAME_OPCODE_TEXT  = 0x1,
    WS_FRAME_OPCODE_BIN   = 0x2,
    WS_FRAME_OPCODE_CLOSE = 0x8,
    WS_FRAME_OPCODE_PING  = 0x9,
    WS_FRAME_OPCODE_PONG  = 0xa
};

int log_to_stderr = 0;

int sn_log(int priority, const char *format, ...){
    va_list ap;
    va_start(ap, format);
    if(log_to_stderr){
         fprintf(stderr, "<%d> %6d %6d ", priority, getpid(), getppid());
        vfprintf(stderr, format, ap);
         fprintf(stderr, "\n");
    }else{
        // Use this to simulate vsyslog
        char s[1024];
        vsnprintf(s, 1024, format, ap);
        syslog(priority, s, strlen(s));
    }
    va_end(ap);
    return 0;
}

uint32_t getipbyfqdn(const char *fqdn){
    struct hostent *p = gethostbyname(fqdn);
    if(p == NULL || p->h_length == 0){
        printf("cannot find host: %s", fqdn);
        return -1;
    }
    return *(uint32_t *)p->h_addr_list[0];
}

int set_sockopt_int(int socket, int family, int key, int value){
    int old;
    socklen_t len = sizeof(old);

    int ret = getsockopt(
        socket,
        family,
        key,
        &old,
        &len
    );
    if(ret < 0){
        perror("getsockopt()");
        return ret;
    }
    sn_log(LOG_DEBUG, "keepalive value %d = %d", key,  old);

    ret = setsockopt(
        socket,
        family,
        key,
        &value,
        sizeof(value)
    );
    if(ret < 0)
        perror("setsockopt()");
    return ret;
}

int set_keepalive(
    int socket,
    int enabled,
    int time,
    int intvl,
    int probes
){
    // see http://tldp.org/HOWTO/html_single/TCP-Keepalive-HOWTO
    int ret;
    if((ret = set_sockopt_int(socket, SOL_SOCKET, SO_KEEPALIVE , enabled)) < 0)
        return ret;

#define chk_and_set(k,v) \
    if(v != 0 && (ret = set_sockopt_int(socket, IPPROTO_TCP, k, v )) < 0) return ret;
    chk_and_set(TCP_KEEPCNT  , probes);
    chk_and_set(TCP_KEEPIDLE , time  );
    chk_and_set(TCP_KEEPINTVL, intvl );
#undef chk_and_set

    return ret;
}

int calc_ws_protocol_ret(const char *challenge, char *response){
    const char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    int len = strlen(challenge) + strlen(magic_string);
    char input[len + 1];
    sprintf(input, "%s%s", challenge, magic_string);

    uint8_t sha1_digest[SHA1HashSize];
    SHA1Context s;
    SHA1Reset(&s);
    SHA1Input(&s, (uint8_t *)input, len);
    SHA1Result(&s, sha1_digest);

    b64_encode(sha1_digest, SHA1HashSize, response, 64);

    return 0;
}

int main(int argc, char *argv[]){

    struct sockaddr_in conn_addr;
    conn_addr.sin_family = AF_INET;

    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    const char *helpstr =
#ifdef TCPT_SERVER
        "TCPTunnel Server\n"
        "\n"
        "%s [-b <addr>] [-h] [-e] <Listen Port> <Listen Path> <Connect Host> <Connect Port>\n"
        "Listen Port        specify websocket server port to listen on\n"
        "Listen Path        specify url path to listen on\n"
        "Connect Host       remote tcp server to connect\n"
        "Connect Port       remote port to connect\n"
#else // TCPT_CLIENT
        "TCPTunnel Client\n"
        "\n"
        "%s [-b <addr>] [-h] [-e] <Listen Port> <Connect URL>\n"
        "\n"
        "Listen Port        specify port to listen on\n"
        "Connect URL        websocket url to connect\n"
#endif
        "-b,  --bind        optional address to bind (default to 0.0.0.0)\n"
        "-h,  --help        print this help.\n"
        "-e,  --stderr      write logs to stderr.\n";

    struct option options[]={
        {"help",   no_argument,       NULL, 'h'},
        {"stderr", no_argument,       NULL, 'e'},
        {"bind",   required_argument, NULL, 'b'},
    };

    for(;;){
        int c = getopt_long(argc, argv, "heb:", options, NULL);
        if(c == -1)
            break;

        switch(c){
        case 'h':
            printf(helpstr, argv[0]);
            return -1;
            break;
        case 'e':
            log_to_stderr = 1;
            break;
        case 'b':
            listen_addr.sin_addr.s_addr = getipbyfqdn(optarg);
            break;
        default:
            break;
        }
    }

#define next_opt (argv[optind++])
#ifdef TCPT_SERVER
    if(argc - optind != 4){
        puts("insufficient argument");
        printf(helpstr, argv[0]);
        return -1;
    }
    listen_addr.sin_port = htons(atoi(next_opt));

    const char *listen_path = next_opt;

    conn_addr.sin_addr.s_addr = getipbyfqdn(next_opt);

    conn_addr.sin_port = htons(atoi(next_opt));

#else // TCPT_CLIENT
    if(argc - optind != 2){
        puts("insufficient argument count");
        printf(helpstr, argv[0]);
        return -1;
    }

    listen_addr.sin_port = htons(atoi(next_opt));

    const char *connect_url = next_opt;

    // Parse connect url
    char connect_url_host[strlen(connect_url) + 1];
    char connect_url_path[strlen(connect_url) + 1];
    if(sscanf(
        connect_url,
        "ws://%[^/]%s",
        connect_url_host,
        connect_url_path
    ) != 2){
        puts("invalid websocket url");
        printf(helpstr, argv[0]);
        return -1;
    }
    if(strrchr(connect_url_host, '[') != NULL){
        puts("ipv6 is not supported yet");
        return -1;
    }

    conn_addr.sin_port = htons(80);
    char *tmp = strchr(connect_url_host, ':');
    if(tmp != NULL){
        // the host has port specified
        *tmp++ = '\0';
        conn_addr.sin_port = htons(atoi(tmp));
    }
        
    conn_addr.sin_addr.s_addr = getipbyfqdn(connect_url_host);

#endif
#undef next_opt

    sn_log(LOG_INFO, "Finished parsing args");

    srand(getpid());

    char buffer[BUFF_LEN];
    size_t len;

    int listenfd = -1;

    for(;;){
        int connfd = socket(PF_INET, SOCK_STREAM, 0);
        if(connect(
            connfd,
            (struct sockaddr *)&conn_addr,
            sizeof(conn_addr)
        ) < 0){
            sn_log(LOG_ERR, "cannot connect to remote server");
            return -1;
        }
        if(set_keepalive(connfd, 1, 60, 30, 20) < 0)
            sn_log(LOG_WARNING, "cannot set keepalive on connfd");

#ifdef TCPT_CLIENT
        const char *http_req_data =
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Protocol: chat\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";

        // Calc a random string for Sec-Websocket-Key
        uint8_t rand_str[16];
        for(int i=0;i<16;i++)
            rand_str[i]=rand()&0xFF;

        char b64ed_rand_str[32], expected_response_str[64];
        b64_encode(rand_str, 16, b64ed_rand_str, 32);

        calc_ws_protocol_ret(b64ed_rand_str, expected_response_str);

        // Form packet
        len = snprintf(
            buffer,
            BUFF_LEN,
            http_req_data,
            connect_url_path,
            connect_url_host,
            htons(conn_addr.sin_port),
            b64ed_rand_str
        );
        len = send(connfd, buffer, len, 0);
        if(len < 0){
            sn_log(LOG_NOTICE, "send to connfd failed");
            shutdown(connfd, SHUT_RDWR);
            return -1;
        }
        sn_log(LOG_INFO,"sent http handshake packet, waiting for response");

        // Wait for response
        len = recv(connfd, buffer, BUFF_LEN - 1, 0);
        if(len < 0){
            sn_log(LOG_NOTICE, "recv from connfd failed");
            shutdown(connfd, SHUT_RDWR);
            return -1;
        }
        buffer[len] = '\0';

        sn_log(LOG_DEBUG, "recv data:\n%*s", len, buffer);

        int ws_checker = 0;

        // Parse response packet
        for(char *p = buffer; ; p=NULL){
            char *line = strtok(p, "\r\n");

            // FIXME: skip checking http header last empty line,
            // due to strtok
            if(line == NULL){
                sn_log(LOG_DEBUG, "reach http eoh");
                break;
            }

            sn_log(LOG_DEBUG, "parsing line: %s", line);
            if(p){
                // We are at the first line
                float version;
                int code;
                if(sscanf(line, "HTTP/%f %d", &version, &code) != 2){
                    sn_log(LOG_ERR, "malformed status line: %s", line);
                    shutdown(connfd, SHUT_RDWR);
                    return -1;
                }
                if(code != 101){
                    sn_log(LOG_ERR, "HTTP status code not 101");
                    shutdown(connfd, SHUT_RDWR);
                    return -1;
                }

            }else{
                // optional headers
                char *key = line;
                char *value = strchr(line, ':');
                if(value == NULL){
                    sn_log(LOG_ERR, "malformed optional header");
                    shutdown(connfd, SHUT_RDWR);
                }
                *value = '\0';

                // strip the leading spaces
                while(*++value == ' ');

#define match(s) if(!strcasecmp(key,(s)))
                match("Connection"){
                    if(strcasecmp(value, "upgrade")){
                        sn_log(LOG_ERR, "Connection is not upgrade");
                        shutdown(connfd, SHUT_RDWR);
                        return -1;
                    }
                    ws_checker++;
                }
                match("Upgrade"){
                    if(strcasecmp(value, "websocket")){
                        sn_log(LOG_ERR, "Upgrade is not websocket");
                        shutdown(connfd, SHUT_RDWR);
                        return -1;
                    }
                    ws_checker++;
                }
                match("Sec-WebSocket-Protocol"){
                    ws_checker++;
                }
                match("Sec-WebSocket-Accept"){
                    if(strcmp(value, expected_response_str)){
                        sn_log(LOG_ERR, "Malformed Sec-WebSocket-Accept");
                        shutdown(connfd, SHUT_RDWR);
                        return -1;
                    }
                    ws_checker++;
                }
#undef match
            }

        
        }
        if(ws_checker != 4){
            sn_log(LOG_ERR, "websocket protocol missing mandatory headers");
            shutdown(connfd, SHUT_RDWR);
            return -1;
        }
        sn_log(LOG_INFO, "Finish parsing handshake headers, start listening to native socket");

#endif // TCPT_CLIENT

        if(listenfd == -1){
            listenfd = socket(PF_INET, SOCK_STREAM, 0);
            if(bind(
                listenfd,
                (const struct sockaddr *)&listen_addr,
                sizeof(listen_addr)
            )){
                sn_log(LOG_ERR, "bind() failed");
                return -1;
            }
            listen(listenfd, 10);

        }
        struct sockaddr_in sin;
        socklen_t sin_len = sizeof(struct sockaddr_in);
        int acceptfd = accept(
            listenfd,
            (struct sockaddr *)&sin,
            &sin_len
        );

        sn_log(LOG_INFO,"got a connection, fork a worker process");

        if(!fork()){

#ifdef TCPT_SERVER
            // Wait for websocket HTTP Handshake
            len = recv(acceptfd, buffer, BUFF_LEN - 1, 0);
            if(len < 0){
                sn_log(LOG_NOTICE, "recv from acceptfd failed");
                shutdown(acceptfd, SHUT_RDWR);
                shutdown(connfd, SHUT_RDWR);
            }
            sn_log(LOG_INFO, "Got http handshake packet");

            buffer[len] = '\0';
            sn_log(LOG_DEBUG, "recv data:\n%*s", len, buffer);

            // Parse the request
            const char *bad_req = 
                "HTTP/1.1 400 Bad Request\r\n"
                "\r\n";

            const char *not_found = 
                "HTTP/1.1 404 Not Found\r\n"
                "\r\n";

            int ws_checker = 0;
            char ws_protocol_ret[64] = "";

            for(char *p = buffer; ; p=NULL){
                char *line = strtok(p, "\r\n");

                // FIXME: skip checking http header last empty line,
                // due to strtok
                if(line == NULL){
                    sn_log(LOG_DEBUG, "reach http eoh");
                    break;
                }

                sn_log(LOG_DEBUG, "parsing line: %s", line);
                if(p){
                    // We are at the first line
                    char method[strlen(line) + 1];
                    char path[strlen(line) + 1];
                    float version;
                    if(sscanf(
                        line,
                        "%s %s HTTP/%f",
                        method,
                        path,
                        &version
                    ) != 3){
                        sn_log(LOG_ERR, "malformed header");
                        send(acceptfd, bad_req, strlen(bad_req), 0);
                        shutdown(connfd, SHUT_RDWR);
                        shutdown(acceptfd, SHUT_RDWR);
                    }

                    sn_log(LOG_DEBUG, "method = %s", method);
                    sn_log(LOG_DEBUG, "path = %s", path);
                    sn_log(LOG_DEBUG, "HTTP version = %.1f", version);

                    if(strcmp(path, listen_path)){
                        sn_log(LOG_ERR, "path mismatch, send 404");
                        send(acceptfd, bad_req, strlen(not_found), 0);
                        shutdown(connfd, SHUT_RDWR);
                        shutdown(acceptfd, SHUT_RDWR);
                    }

                }else{
                    // optional headers
                    char *key = line;
                    char *value = strchr(line, ':');
                    if(value == NULL){
                        sn_log(LOG_ERR, "malformed optional header");
                        send(acceptfd, bad_req, strlen(bad_req), 0);
                        shutdown(connfd, SHUT_RDWR);
                        shutdown(acceptfd, SHUT_RDWR);
                    }
                    *value = '\0';

                    // strip the leading spaces
                    while(*++value == ' ');

#define match(s) if(!strcasecmp(key,(s)))
                    match("Connection"){
                        if(strcasecmp(value, "upgrade")){
                            sn_log(LOG_ERR, "Connection is not upgrade");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd, SHUT_RDWR);
                            shutdown(acceptfd, SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Upgrade"){
                        if(strcasecmp(value, "websocket")){
                            sn_log(LOG_ERR, "Upgrade is not websocket");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd, SHUT_RDWR);
                            shutdown(acceptfd, SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Sec-WebSocket-Version"){
                        if(strcmp(value, "13")){
                            sn_log(LOG_ERR, "Sec-WebSocket-Version is not 13");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd, SHUT_RDWR);
                            shutdown(acceptfd, SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Sec-WebSocket-Key"){
                        if(calc_ws_protocol_ret(value, ws_protocol_ret)){
                            sn_log(LOG_ERR, "Malformed Sec-WebSocket-Key");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd, SHUT_RDWR);
                            shutdown(acceptfd, SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Sec-WebSocket-Protocol"){
                        ws_checker++;
                    }
#undef match
                }

            
            }
            if(ws_checker == 0){
                sn_log(LOG_INFO, "http request, send 404");
                send(acceptfd, bad_req, strlen(not_found), 0);
                shutdown(connfd, SHUT_RDWR);
                shutdown(acceptfd, SHUT_RDWR);
                return -1;
            }
            if(ws_checker != 5){
                sn_log(LOG_ERR, "websocket protocol missing mandatory headers");
                send(acceptfd, bad_req, strlen(bad_req), 0);
                shutdown(connfd, SHUT_RDWR);
                shutdown(acceptfd, SHUT_RDWR);
                return -1;
            }
            sn_log(LOG_INFO, "Finish parsing handshake headers, write response");

            // Form handshake response
            const char *ret =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Protocol: chat\r\n"
                "Sec-WebSocket-Accept: %s\r\n"
                "\r\n";

            len = snprintf(buffer, BUFF_LEN, ret, ws_protocol_ret);
            len = send(acceptfd, buffer, len, 0);
            if(len < 0){
                sn_log(LOG_NOTICE, "send to connfd failed");
                shutdown(connfd, SHUT_RDWR);
                shutdown(acceptfd, SHUT_RDWR);
                return -1;
            }
            sn_log(LOG_INFO, "sent handshake response, entering full duplex");

#endif //TCPT_SERVER

#ifdef TCPT_SERVER
            int encodefd = connfd  ; // data from this fd will be encoded
            int decodefd = acceptfd; // data from this fd will be decoded
#else // TCPT_CLIENT
            int encodefd = acceptfd; // data from this fd will be encoded
            int decodefd = connfd  ; // data from this fd will be decoded
#endif
            if(fork()){
                sn_log(LOG_INFO, "encode process started");
                for(;;){
                    // Reserve 14 bytes for websocket header
                    char *p = buffer + 14;
                    len = recv(encodefd, buffer + 14, BUFF_LEN - 14, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "recv from encodefd failed");
                        shutdown(encodefd, SHUT_RD);
                        shutdown(decodefd, SHUT_WR);
                        return -1;
                    }
                    if(len == 0)
                        break;

                    // Encode the packet

                    sn_log(LOG_DEBUG, "content length = %llu", len);

                    // process varlength header
                    size_t content_len = len;
                    len += 2; // mandatory header

                    if(content_len > 0xffff){
                        *(uint64_t *)(p -= 8) = _htonll(content_len);
                        content_len = 127;
                        len += 8;
                    }
                    else if(content_len > 126){
                        *(uint16_t *)(p -= 2) = htons(content_len);
                        content_len = 126;
                        len += 2;
                    }

                    sn_log(LOG_DEBUG, "send len = %llu", len);

                    // form header
                    // TODO: implement masking
                    WS_FRAME_HDR *p_header = (WS_FRAME_HDR *)(p -= 2);
                    p_header->fin    = 1;
                    p_header->rsv1   = 0;
                    p_header->rsv2   = 0;
                    p_header->rsv3   = 0;
                    p_header->opcode = WS_FRAME_OPCODE_BIN;
                    p_header->mask   = 0;
                    p_header->len    = content_len;

                    // convert byte order
                    *(uint16_t *)p_header = htons(*(uint16_t *)p_header);

                    len = send(decodefd, p, len, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "send to decodefd failed");
                        shutdown(decodefd, SHUT_WR);
                        shutdown(encodefd, SHUT_RD);
                        return -1;
                    }
                }
                shutdown(encodefd, SHUT_RD);
                shutdown(decodefd, SHUT_WR);
            }else{
                sn_log(LOG_INFO, "decode process started");
                for(;;){
                    len = recv(decodefd, buffer, BUFF_LEN, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "recv from decodefd failed");
                        shutdown(decodefd, SHUT_RD);
                        shutdown(encodefd, SHUT_WR);
                        return -1;
                    }
                    if(len == 0)
                        break;

                    // Decode the packet

                    char *p = buffer;

                    WS_FRAME_HDR *p_header = (WS_FRAME_HDR *)p;
                    // convert byte order
                    *(uint16_t *)p_header = htons(*(uint16_t *)p_header);

                    sn_log(
                        LOG_DEBUG,
                        "fin: %u\n",
                        "rsv1: %u\n",
                        "rsv2: %u\n",
                        "rsv3: %u\n",
                        "opcode: %u\n",
                        "mask: %u\n",
                        "len: %u\n",
                        p_header->fin,
                        p_header->rsv1,
                        p_header->rsv2,
                        p_header->rsv3,
                        p_header->opcode,
                        p_header->mask,
                        p_header->len
                    );

                    p += 2;
                    len -= 2; // mandatory header

                    size_t content_len = p_header->len;

                    if(content_len == 127){
                        content_len = _htonll(*(uint64_t *)p);
                        p += 8;
                        len -= 8;
                    }
                    else if(content_len == 126){
                        content_len = htons(*(uint16_t *)p);
                        p += 2;
                        len -= 2;
                    }

                    // check length
                    sn_log(
                        LOG_DEBUG,
                        "content_len = %llu, calculated content len = %llu",
                        content_len,
                        len
                    );
                    if(content_len != len){
                        // TODO: tcp framing
                        sn_log(LOG_ERR, "content length mismatch");
                        shutdown(encodefd, SHUT_WR);
                        shutdown(decodefd, SHUT_RD);
                        return -1;
                    }

                    if(p_header->mask == 1){
                        sn_log(LOG_DEBUG, "masked frame, decoding");

                        // get mask from header
                        char *mask = p;
                        p += 4;

                        // apply mask bytely
                        // TODO: stub implementation here
                        for(int i = 0; i < len; i++)
                            p[i] ^= mask[i%4];
                    }

                    switch(p_header->opcode){
                    case WS_FRAME_OPCODE_BIN:
                        len = send(encodefd, p, len, 0);
                        if(len < 0){
                            sn_log(LOG_NOTICE, "send to encodefd failed");
                            shutdown(encodefd, SHUT_WR);
                            shutdown(decodefd, SHUT_RD);
                            return -1;
                        }

                        break;

                    default:
                        sn_log(LOG_NOTICE, "opcode %d not implemented, drop", p_header->opcode);
                        break;
                    }

                }
                shutdown(decodefd, SHUT_RD);
                shutdown(encodefd, SHUT_WR);
            }
            return 0;
        }
    }
    return 0;
}

