#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <getopt.h>
#include <netdb.h>

#include "sha1.h"
#include "b64.h"

#define BUFF_LEN 32768

int log_to_stderr = 0;

int sn_log(int priority, const char *format, ...){
    va_list ap;
    va_start(ap, format);
    if(log_to_stderr){
         fprintf(stderr, "<%d> ", priority);
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


static struct option options[]={
    {"help",         no_argument,       NULL, 'h'},
    {"stderr",       no_argument,       NULL, 'e'},
};

int main(int argc, char *argv[]){

    const char *helpstr =
#ifdef TCPT_SERVER
        "TCPTunnel Server\n"
        "\n"
        "%s [-h] [-e] <Listen Port> <Connect URL>\n"
        "\n"
        "Listen Port        specify port to listen on\n"
        "Connect URL        websocket url to connect\n"
#endif
#ifdef TCPT_CLIENT
        "TCPTunnel Client\n"
        "\n"
        "%s [-h] [-e] <Listen Path> <Connect URL>\n"
        "Listen Path        specify path to listen on\n"
        "Connect Host       remote tcp server to connect\n"
        "Connect Port       remote port to connect\n"
#endif
        "-h,  --help        print this help.\n"
        "-e,  --stderr      write logs to stderr.\n";

    for(;;){
        int c = getopt_long(argc, argv, "he", options, NULL);
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
        default:
            break;
        }
    }

    struct sockaddr_in conn_addr;
    conn_addr.sin_family = AF_INET;

    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);


#define next_opt (argv[optind++])
#ifdef TCPT_SERVER
    if(argc - optind != 3){
        puts("insufficient argument count");
        printf(helpstr, argv[0]);
        return -1;
    }
    const char *listen_path = next_opt;

    const char *connect_host = next_opt;
    struct hostent *p = gethostbyname(connect_host);
    if(p == NULL || p->h_length == 0){
        printf("cannot find host: %s",connect_host);
        return -1;
    }
    conn_addr.sin_addr.s_addr = *(uint32_t*)p->h_addr_list[0];

    conn_addr.sin_port = htons(atoi(next_opt));

#endif
#ifdef TCPT_CLIENT
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
        
    struct hostent *p = gethostbyname(connect_url_host);
    if(p == NULL || p->h_length == 0){
        printf("cannot find host: %s",connect_url_host);
        return -1;
    }
    conn_addr.sin_addr.s_addr = *(uint32_t*)p->h_addr_list[0];

#endif
#undef next_opt


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
            fputs("Cannot connect to remote server\n", stderr);
            return -1;
        }

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
            shutdown(connfd,SHUT_RDWR);
            return -1;
        }

        // Wait for response
        len = recv(connfd, buffer, BUFF_LEN, 0);
        if(len < 0){
            sn_log(LOG_NOTICE, "recv from connfd failed");
            shutdown(connfd,SHUT_RDWR);
            return -1;
        }

        int ws_checker = 0;

        // Parse response packet
        for(char *p = buffer; ; p=NULL){
            char *line = strtok(p, "\n");
            if(line[0] == '\r'){
                sn_log(LOG_DEBUG, "reach http eoh");
                break;
            }
            if(line[0] == '\0'){
                sn_log(LOG_INFO, "reached EOP, but no http EOH found");
                shutdown(connfd,SHUT_RDWR);
                return -1;
            }
            line[strlen(line)-2] = '\0'; // trim trailing '\r'

            if(p){
                // We are at the first line
                float version;
                int code;
                sscanf(line, "HTTP/%f %d", &version, &code);
                if(code != 101){
                    sn_log(LOG_ERR, "HTTP status code not 101");
                    shutdown(connfd,SHUT_RDWR);
                    return -1;
                }

            }else{
                // optional headers
                char *key = line;
                char *value = strchr(line, ':');
                if(value == NULL){
                    sn_log(LOG_ERR, "malformed optional header");
                    shutdown(connfd,SHUT_RDWR);
                }
                *value = '\0';

                // strip the leading spaces
                while(*++value == ' ');

#define match(s) if(!strcasecmp(key,(s)))
                match("Connection"){
                    if(strcasecmp(value, "upgrade")){
                        sn_log(LOG_ERR, "Connection is not upgrade");
                        shutdown(connfd,SHUT_RDWR);
                        return -1;
                    }
                    ws_checker++;
                }
                match("Upgrade"){
                    if(strcasecmp(value, "websocket")){
                        sn_log(LOG_ERR, "Upgrade is not websocket");
                        shutdown(connfd,SHUT_RDWR);
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
                        shutdown(connfd,SHUT_RDWR);
                        return -1;
                    }
                    ws_checker++;
                }
#undef match
            }

        
        }
        if(ws_checker != 4){
            sn_log(LOG_ERR, "websocket protocol missing mandatory headers");
            shutdown(connfd,SHUT_RDWR);
            return -1;
        }
        sn_log(LOG_DEBUG, "Finish parsing handshake headers, start listening to native socket");

#endif // TCPT_CLIENT

        if(listenfd == -1){
            listenfd = socket(PF_INET, SOCK_STREAM, 0);
            bind(
                listenfd,
                (const struct sockaddr *)&listen_addr,
                sizeof(listen_addr)
            );
            listen(listenfd, 10);

        }
        struct sockaddr_in sin;
        socklen_t sin_len = sizeof(struct sockaddr_in);
        int acceptfd = accept(
            listenfd,
            (struct sockaddr *)&sin,
            &sin_len
        );

        if(!fork()){

#ifdef TCPT_SERVER
            // Wait for websocket HTTP Handshake
            len = recv(connfd, buffer, BUFF_LEN, 0);
            if(len < 0){
                sn_log(LOG_NOTICE, "recv from connfd failed");
                shutdown(connfd,SHUT_RDWR);
                shutdown(acceptfd,SHUT_RDWR);
            }
            sn_log(LOG_DEBUG, "Got http handshake packet");

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
                char *line = strtok(p, "\n");
                if(line[0] == '\r'){
                    sn_log(LOG_DEBUG, "reach http eoh");
                    break;
                }
                if(line[0] == '\0'){
                    sn_log(LOG_INFO, "reached EOP, but no http EOH found");
                    send(acceptfd, bad_req, strlen(bad_req), 0);
                    shutdown(connfd,SHUT_RDWR);
                    shutdown(acceptfd,SHUT_RDWR);
                    return -1;
                }
                line[strlen(line)-2] = '\0'; // trim trailing '\r'

                if(p){
                    // We are at the first line
                    // Simply ignore it
                }else{
                    // optional headers
                    char *key = line;
                    char *value = strchr(line, ':');
                    if(value == NULL){
                        sn_log(LOG_ERR, "malformed optional header");
                        send(acceptfd, bad_req, strlen(bad_req), 0);
                        shutdown(connfd,SHUT_RDWR);
                        shutdown(acceptfd,SHUT_RDWR);
                    }
                    *value = '\0';

                    // strip the leading spaces
                    while(*++value == ' ');

#define match(s) if(!strcasecmp(key,(s)))
                    match("Connection"){
                        if(strcasecmp(value, "upgrade")){
                            sn_log(LOG_ERR, "Connection is not upgrade");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd,SHUT_RDWR);
                            shutdown(acceptfd,SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Upgrade"){
                        if(strcasecmp(value, "websocket")){
                            sn_log(LOG_ERR, "Upgrade is not websocket");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd,SHUT_RDWR);
                            shutdown(acceptfd,SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Sec-WebSocket-Version"){
                        if(strcmp(value, "13")){
                            sn_log(LOG_ERR, "Sec-WebSocket-Version is not 13");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd,SHUT_RDWR);
                            shutdown(acceptfd,SHUT_RDWR);
                            return -1;
                        }
                        ws_checker++;
                    }
                    match("Sec-WebSocket-Key"){
                        if(!calc_ws_protocol_ret(value, ws_protocol_ret)){
                            sn_log(LOG_ERR, "Malformed Sec-WebSocket-Key");
                            send(acceptfd, bad_req, strlen(bad_req), 0);
                            shutdown(connfd,SHUT_RDWR);
                            shutdown(acceptfd,SHUT_RDWR);
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
            if(!ws_checker == 0){
                sn_log(LOG_INFO, "http request, send 404");
                send(acceptfd, bad_req, strlen(not_found), 0);
                shutdown(connfd,SHUT_RDWR);
                shutdown(acceptfd,SHUT_RDWR);
                return -1;
            }
            if(ws_checker != 5){
                sn_log(LOG_ERR, "websocket protocol missing mandatory headers");
                send(acceptfd, bad_req, strlen(bad_req), 0);
                shutdown(connfd,SHUT_RDWR);
                shutdown(acceptfd,SHUT_RDWR);
                return -1;
            }
            sn_log(LOG_DEBUG, "Finish parsing handshake headers, write response");

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
                shutdown(connfd,SHUT_RDWR);
                shutdown(acceptfd,SHUT_RDWR);
                return -1;
            }
            sn_log(LOG_DEBUG, "sent handshake response, entering full duplex");

#endif //TCPT_SERVER

            if(fork()){
                sn_log(LOG_DEBUG, "read from connfd process started");
                for(;;){
                    len = recv(connfd, buffer, BUFF_LEN, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "recv from connfd failed");
                        shutdown(connfd,SHUT_RD);
                        shutdown(acceptfd,SHUT_WR);
                        return -1;
                    }
                    if(len == 0)
                        break;
                    len = send(acceptfd, buffer, len, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "send to acceptfd failed");
                        shutdown(acceptfd,SHUT_WR);
                        shutdown(connfd,SHUT_RD);
                        return -1;
                    }
                }
                shutdown(connfd,SHUT_RD);
                shutdown(acceptfd,SHUT_WR);
            }else{
                sn_log(LOG_DEBUG, "write to connfd process started");
                for(;;){
                    len = recv(acceptfd, buffer, BUFF_LEN, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "recv from acceptfd failed");
                        shutdown(acceptfd,SHUT_RD);
                        shutdown(connfd,SHUT_WR);
                        return -1;
                    }
                    if(len == 0)
                        break;
                    len = send(connfd, buffer, len, 0);
                    if(len < 0){
                        sn_log(LOG_NOTICE, "send to connfd failed");
                        shutdown(connfd,SHUT_WR);
                        shutdown(acceptfd,SHUT_RD);
                        return -1;
                    }
                }
                shutdown(acceptfd,SHUT_RD);
                shutdown(connfd,SHUT_WR);
            }
            return 0;
        }
    }
    return 0;
}

