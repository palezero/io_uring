#include <liburing.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <arpa/inet.h>
 
 
#define BUFFER_LENGTH           2048
#define MAX_MESSAGE_LEN         2048
#define BACKLOG                 512
#define SERVER_PORT             7777
#define MAX_CONNECTIONS         4096
//#define IORING_FEAT_FAST_POLL   1U << 5

enum{
    ACCEPT,
    READ,
    WRITE,
    LOG,
};
 

typedef int (*NCALLBACK)(void *arg, struct io_uring_cqe *cqe);

typedef struct _accept_arg{
    int fd;
    struct sockaddr *client_addr;
    socklen_t *client_len;
    unsigned flags;
}accept_arg;

typedef struct _normal_arg{
    int fd;
    size_t size;
    unsigned flags;
}normal_args;

typedef struct _revent {
    int fd;
    unsigned type;
    NCALLBACK callback;
    char buffer[BUFFER_LENGTH];
} revent;
 
typedef struct _rreactor {
    struct io_uring *ring;
    revent *ring_events;
    int log_fd;
} rreactor;


int recv_ce(void *arg, struct io_uring_cqe *cqe);
int send_ce(void *arg, struct io_uring_cqe *cqe);
int accept_ce(void *arg, struct io_uring_cqe *cqe);
int log_ce(void *arg, struct io_uring_cqe *cqe);

int log_file = 0;
 
int init_sock(unsigned short port) 
{
 
    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);
    const int val = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));


    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
 
    if(bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("Error binding socket..\n");
        exit(1);
    }
 
    if (listen(listen_fd, 20) < 0) {
        perror("listen");
    }
 
    return listen_fd;
}
 
 
int rreactor_init(rreactor *reactor) 
{
 
    if (reactor == NULL)  return -1;
    memset(reactor, 0, sizeof(rreactor));
 

    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    reactor->ring = (struct io_uring*)malloc(sizeof(struct io_uring));

    if(io_uring_queue_init_params(4096, reactor->ring, &params) < 0){
        perror("io_uring_init_failed...\n");
        exit(1);
    }

    if(!(params.features & IORING_FEAT_FAST_POLL)){
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }
    
    reactor->ring_events = (revent *)malloc(MAX_CONNECTIONS * sizeof(revent));
    if (reactor->ring_events == NULL) {
 
        perror("malloc reactor->ring_events");
        io_uring_queue_exit(reactor->ring);
        return -3;
    }
    memset(reactor->ring_events, 0, MAX_CONNECTIONS * sizeof(revent));

    reactor->log_fd = open("./log", O_RDWR | O_APPEND);
    if(reactor->log_fd < 0){
        printf("The log file can't open...\n");
        exit(0);
    }
 
    return 0;
 
}
 
void rreactor_destroy(rreactor *reactor) 
{
    io_uring_queue_exit(reactor->ring);
    free(reactor->ring_events);
    close(reactor->log_fd);
}
 
void rreactor_event_set(revent *rev, int fd, NCALLBACK callback, unsigned type) 
{
    rev->fd = fd;
    rev->callback = callback;
    rev->type = type;
}
 
int rreactor_event_add(rreactor *reactor, revent *rev, void* args, unsigned  type) 
{

    struct io_uring_sqe *sqe = io_uring_get_sqe(reactor->ring);
    if(type == ACCEPT){
        accept_arg *ac_args = (accept_arg*)args;
        rreactor_event_set(rev, ac_args->fd, accept_ce, type);

        io_uring_prep_accept(sqe, ac_args->fd, ac_args->client_addr, ac_args->client_len, 0);
        io_uring_sqe_set_flags(sqe, ac_args->flags);

        io_uring_sqe_set_data(sqe, rev);
    }
    else if(type == READ){
        normal_args *nor_args = (normal_args*)args;
        rreactor_event_set(rev, nor_args->fd, recv_ce, type);

        io_uring_prep_recv(sqe, nor_args->fd, reactor->ring_events[nor_args->fd].buffer, nor_args->size, 0);
        io_uring_sqe_set_flags(sqe, nor_args->flags);

        io_uring_sqe_set_data(sqe, rev);
    }
    else if(type == WRITE){
        normal_args *nor_args = (normal_args*)args;
        rreactor_event_set(rev, nor_args->fd, send_ce, type);
        
        io_uring_prep_send(sqe, nor_args->fd, reactor->ring_events[nor_args->fd].buffer, nor_args->size, 0);
        io_uring_sqe_set_flags(sqe, nor_args->flags);

        io_uring_sqe_set_data(sqe, rev);
    }
    else if(type == LOG){
        normal_args *nor_args = (normal_args*)args;
        rreactor_event_set(rev, nor_args->fd, log_ce, type);

        char *buffer = (char*)malloc(sizeof(char)* nor_args->size);
        memcpy(buffer, rev->buffer, nor_args->size);
        io_uring_prep_write(sqe, nor_args->fd, buffer, nor_args->size, 0);
        io_uring_sqe_set_flags(sqe, nor_args->flags);

        io_uring_sqe_set_data(sqe, rev);
    }
    return 0;
}
 
// int nreactor_event_del(int epfd, nevent *ev) {
 
//     struct epoll_event ep_ev = {0, {0}};
    
//     if (ev->status != 1) {
//         return -1;
//     }
 
//     ev->status = 0;
 
//     epoll_ctl(epfd, EPOLL_CTL_DEL, ev->fd, NULL);
 
//     return 0;
 
// }
 
int recv_ce(void *arg, struct io_uring_cqe *cqe) 
{
    rreactor* reactor = (rreactor*)arg;
    int bytes_read = cqe->res;
    revent *user_data = (revent*)io_uring_cqe_get_data(cqe);
    

    if(bytes_read <= 0){
        io_uring_cqe_seen(reactor->ring, cqe);
        shutdown(user_data->fd, SHUT_RDWR);
    }else{
        io_uring_cqe_seen(reactor->ring, cqe);
        revent* rev = reactor->ring_events + user_data->fd;
        normal_args nor_args;
        nor_args.fd = user_data->fd;
        nor_args.size = bytes_read;
        nor_args.flags = 0;
        rreactor_event_add(reactor, rev, &nor_args, WRITE);

        if(log_file == 1){
            struct sockaddr_in peer_addr;
            int peer_len;
            getpeername(user_data->fd, (struct sockaddr*)&peer_addr, &peer_len);
            char ip_addr[INET_ADDRSTRLEN]; 

            rev = reactor->ring_events + reactor->log_fd;
            nor_args.fd = reactor->log_fd;
            char *address = inet_ntop(AF_INET, &peer_addr.sin_addr, ip_addr, sizeof(ip_addr));
            int port = ntohs(peer_addr.sin_port);
            int size = snprintf(rev->buffer, BUFFER_LENGTH, "[Receive]:receiv %d bytes from %s:%d\n", bytes_read, address, port);
            nor_args.size = size;
            rreactor_event_add(reactor, rev, &nor_args, LOG);
        }
    }
    
    return bytes_read;
}
 
int send_ce(void *arg, struct io_uring_cqe *cqe) 
{
    rreactor* reactor = (rreactor*)arg;
    revent *user_data = (revent*)io_uring_cqe_get_data(cqe);
    io_uring_cqe_seen(reactor->ring, cqe);

    normal_args nor_args;
    nor_args.fd = user_data->fd;
    nor_args.size = MAX_MESSAGE_LEN;
    nor_args.flags = 0;
    revent* rev = reactor->ring_events + user_data->fd;
    rreactor_event_add(reactor, rev, &nor_args, READ);

    if(log_file == 1){
        struct sockaddr_in peer_addr;
        int peer_len;
        getpeername(user_data->fd, (struct sockaddr*)&peer_addr, &peer_len);
        char ip_addr[INET_ADDRSTRLEN]; 

        rev = reactor->ring_events + reactor->log_fd;
        nor_args.fd = reactor->log_fd;
        char *address = inet_ntop(AF_INET, &peer_addr.sin_addr, ip_addr, sizeof(ip_addr));
        int port = ntohs(peer_addr.sin_port);
        int size = snprintf(rev->buffer, BUFFER_LENGTH, "[Sent]:sent %d bytes to %s:%d\n", cqe->res, address, port);
        nor_args.size = size;
        rreactor_event_add(reactor, rev, &nor_args, LOG);
    }

    return cqe->res;
}
 
int accept_ce(void *arg, struct io_uring_cqe *cqe) 
{
    rreactor* reactor = (rreactor*)arg;
    int sock_con_fd = cqe->res;

    revent* user_data = (revent*)io_uring_cqe_get_data(cqe);
    io_uring_cqe_seen(reactor->ring, cqe);
    revent *rev;
    
    if(sock_con_fd > 0){
        normal_args nor_args;

        rev = reactor->ring_events + sock_con_fd;
        nor_args.fd = sock_con_fd;
        nor_args.size = MAX_MESSAGE_LEN;
        nor_args.flags = 0;
        rreactor_event_add(reactor, rev, &nor_args, READ);
        
        if(log_file == 1){
            struct sockaddr_in peer_addr;
            int peer_len;
            getpeername(sock_con_fd, (struct sockaddr*)&peer_addr, &peer_len);
            char ip_addr[INET_ADDRSTRLEN]; 
            rev = reactor->ring_events + reactor->log_fd;
            nor_args.fd = reactor->log_fd;
            char *address = inet_ntop(AF_INET, &peer_addr.sin_addr, ip_addr, sizeof(ip_addr));
            int port = ntohs(peer_addr.sin_port);
            int size = snprintf(rev->buffer, BUFFER_LENGTH, "[Connect]:connected the client: %s:%d\n", address, port);
            nor_args.size = size;
            rreactor_event_add(reactor, rev, &nor_args, LOG);
        }
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    accept_arg ac_args;
    ac_args.fd = user_data->fd;
    ac_args.client_addr = &client_addr;
    ac_args.client_len = &client_len;
    ac_args.flags = 0;
    rev = reactor->ring_events + ac_args.fd;
    rreactor_event_add(reactor, rev, &ac_args, ACCEPT);

    return 0;
}
 
int log_ce(void *arg, struct io_uring_cqe *cqe)
{
    rreactor* reactor = (rreactor*)arg;
    revent *user_data = (revent*)io_uring_cqe_get_data(cqe);
    io_uring_cqe_seen(reactor->ring, cqe);

    //printf("System have log %d bytes in log file[descripter: %d]...\n", cqe->res, user_data->fd);
    return 0;
}
 
int rreactor_addlistener(rreactor *reactor, int listen_fd) 
{
 
    if (reactor == NULL || reactor->ring_events == NULL) {
        return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    accept_arg ac_args;
    ac_args.fd = listen_fd;
    ac_args.client_addr = &client_addr;
    ac_args.client_len = &client_len;
    ac_args.flags = 0;
    rreactor_event_add(reactor, reactor->ring_events + ac_args.fd, &ac_args, ACCEPT);
    return 0;
 
}
 
int rreactor_run(rreactor *reactor) 
{
 
    if (reactor == NULL) return -1;
    if (reactor->ring_events == NULL) return -1;
 
    while (1) {
        struct io_uring_cqe *cqe;
        int ret;
        io_uring_submit(reactor->ring);

        ret = io_uring_wait_cqe(reactor->ring, &cqe);
        if(ret != 0){
            perror("Error io_uring_wait_cqe\n");
            exit(1);
        }

        struct io_uring_cqe *cqes[BACKLOG];
        int cqe_count = io_uring_peek_batch_cqe(reactor->ring, cqes, sizeof(cqes) / sizeof(cqes[0]));

        for(int i = 0;i < cqe_count;i++){
            struct io_uring_cqe *cqe = cqes[i];
            revent *user_data = (revent*)io_uring_cqe_get_data(cqe);
            user_data->callback(reactor, cqe);
        }

    }
 
}
 
 
#if 1
 
int main(int argc, char *argv[]) 
{
 
    unsigned short port = SERVER_PORT;
    if (argc == 2) {
        char *arg = "-f";
        if(strcmp(arg, argv[1]) == 0){
            log_file = 1;
        }
    }
 
    int listen_fd = init_sock(port);
 
    rreactor *reactor = (rreactor *)malloc(sizeof(rreactor));
    rreactor_init(reactor);
 
    rreactor_addlistener(reactor, listen_fd);
    rreactor_run(reactor);
 
    rreactor_destroy(reactor);
    close(listen_fd);
 
    free(reactor);
 
    return 0;
}
 
 
#endif