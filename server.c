#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFF_LEN 32768

int main(int argc, char *argv[]){

    struct sockaddr_in conn_addr;
    conn_addr.sin_family = AF_INET;
    conn_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    conn_addr.sin_port = htons(1080);

    struct sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htons(8278); // TCPT

    int listenfd = -1;

    for(;;){
        int connfd = socket(PF_INET, SOCK_STREAM, 0);
        if(connect(connfd, (struct sockaddr *)&conn_addr, sizeof(conn_addr)) < 0)
            return -1;

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
        int len = sizeof(struct sockaddr_in);
        int acceptfd = accept(
            listenfd,
            (struct sockaddr *)&sin,
            &len
        );

        if(!fork()){
            if(fork()){
                char buffer[BUFF_LEN];
                for(;;){
                    int len = recv(connfd, buffer, BUFF_LEN, 0);
                    if(len == 0)
                        break;
                    send(acceptfd, buffer, len, 0);
                }
                close(acceptfd);
                close(connfd);
            }else{
                char buffer[BUFF_LEN];
                for(;;){
                    int len = recv(acceptfd, buffer, BUFF_LEN, 0);
                    if(len == 0)
                        break;
                    send(connfd, buffer, len, 0);
                }
                close(connfd);
                close(acceptfd);
            }
        }
    }
}

