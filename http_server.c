#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include<pthread.h>
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<errno.h>
#include<signal.h>
#include <sys/mman.h>
#include<fcntl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443  
#define BUF_SIZE 4096
#define WAIT_QUEUE 64
int print_log = 0;
int err_message(char* message)
{
    if(print_log)
        perror(message);
}
int log_header(const char* prompt, char* message)
{   
    if(print_log)
        printf(prompt, message);
}
int cyc_send(int sockfd,char* message,int length)
{
    int i ,send_len;
    i = 0;
    while(i < length)
    {
        send_len = send(sockfd,message + i,length - i,0);
        if((send_len < 0 && errno != EINTR) || send_len == 0)
        {
            err_message("send()");
            return -1;
        }
        else if(send_len < 0 && errno == EINTR) 
            continue;
        else 
            i = i + send_len;
    }
    return 0;
}
int cyc_recv(int sockfd, char* message, int length)
{
    int recv_len;
    while (1) {
        recv_len = recv(sockfd, message, length,0);
        if((recv_len < 0 && errno != EINTR) || recv_len == 0) 
        {
            err_message("recv()");
            return -1;
        }
        else if(recv_len < 0 && errno == EINTR) continue;
        return recv_len;
    }
}
int cyc_SSL_send(SSL *ssl,char* message,int length)
{
    int i, send_len;
    i = 0;
    while(i < length)
    {
        send_len = SSL_write(ssl,message + i,length - i);
        if (send_len <= 0) 
        {
            err_message("SSL_write()");
            int ssl_err = SSL_get_error(ssl,send_len);
            if(ssl_err == SSL_ERROR_NONE || ssl_err == SSL_ERROR_WANT_READ ||ssl_err == SSL_ERROR_WANT_WRITE)
                continue;  //repeat
            else if(ssl_err == SSL_ERROR_SYSCALL) {
                if(errno == EAGAIN)
                    continue;
                else if(errno == EINTR)
                    continue;
                else 
                    return -1;
            }
            else
                return -1;
        } 
        i = i + send_len;
    }
    return 0;
}
int cyc_SSL_recv(SSL *ssl, char* message, int length)
{
    int recv_len;
    while (1) {
        recv_len = SSL_read(ssl, message, length);
        if(recv_len == 0)
        {
            err_message("SSL_read()");
            return -1;
        }
        else if (recv_len < 0) 
        {
            int ssl_err = SSL_get_error(ssl,recv_len);
            err_message("SSL_read()");
            if(ssl_err == SSL_ERROR_NONE || ssl_err == SSL_ERROR_WANT_READ ||ssl_err == SSL_ERROR_WANT_WRITE)
                continue;  //repeat
            else if(ssl_err == SSL_ERROR_SYSCALL) {
                if(errno == EAGAIN)
                    continue;
                else if(errno == EINTR)
                    continue;
                else 
                    return -1;
            }
            else
                return -1;
        }
        return recv_len; 
    }
}
 // url: https://www.xxx.com/path
void parse_url(char* url, char* filename)
{
    char* path;
    char* locator = strstr(url,"://");
    if(locator)
        path = strstr(locator + strlen("://"),"/") + 1;
    else 
        path = url + 1;
    strcpy(filename,path);       
}
void parse_range(char* buf,char** range_ptr, char* line)
{
    strtok(buf,"\n");
    *range_ptr = NULL;
    while(strcpy(line,strtok(NULL, "\n")))
    {
        if(strlen(line) == 1) break;//"\r"
        if(strstr(line,"Range")) 
        {
            *range_ptr = strstr(line,"=") + 1;
            break;
        }
    }
}
void parse_host(char* buf, char** host_ptr, char* line)
{
    strtok(buf,"\n");
    *host_ptr = NULL;
    while(strcpy(line,strtok(NULL, "\n")))
    {
        if(strlen(line) == 1) break;//"\r"
        if(strstr(line,"Host: ")) 
        {
            *host_ptr = line + 6;
            break;
        }
    }
}
void parse_type(char* filename,char* filetype)
{
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg"))
        strcpy(filetype, "image/jpeg");
    else if(strstr(filename, ".mp4"))
        strcpy(filetype, "video/mp4");
    else
        strcpy(filetype, "text/plain");
}
//TODO:判断文件是否存在+重定向
void http_response(int client_fd,char* filename,char* response,char* host)
{
    char filetype[BUF_SIZE];
    char redirect_url[BUF_SIZE];
    parse_type(filename,filetype);

    strcpy(response,"HTTP/1.1 301 Moved Permanently\r\n");
    if(host)
    {
        int len = strlen(host);
        host[len - 1] = 0; //'r' -> '\0'
        sprintf(redirect_url,"Location: https://%s/%s",host, filename);
    }
    else
        sprintf(redirect_url,"Location: https://%s/%s","10.0.0.1", filename);
    strcat(response,redirect_url);
    strcat(response,"\r\n");
    strcat(response,"Server: HTTP_SERVER\r\n");
    strcat(response,"Content-Type: ");
    strcat(response,filetype);
    log_header("[HTTP response]:\n%s\n",response);
    strcat(response,"\r\n\r\n");
    cyc_send(client_fd,response,strlen(response));
}
//TODO:判断文件是否存在+判断是否分片+处理分片
void https_response(SSL* ssl, char* filename, char*response, char* range)
{
    char filetype[BUF_SIZE];
    int start,end,total_len;
    char num_str[32];
    struct stat file_status;

    stat(filename,&file_status);
    parse_type(filename,filetype);
    if(access(filename,F_OK) == -1) //not exist
        strcpy(response,"HTTP/1.1 404 NOT FOUND\r\n");
    else {
        if(range == NULL)
        {
            strcpy(response,"HTTP/1.1 200 OK\r\n");
            start = 0;
            end = file_status.st_size - 1;
        }
        else
        {
            strcpy(response,"HTTP/1.1 206 Partial Content\r\n");
            int len = strlen(range);
            range[len - 1] = 0; //'r' -> '\0'
            if(range[len - 2] == '-') //"100-"
            {
                sscanf(range,"%d-",&start);
                end = file_status.st_size - 1;
            }
            else
                sscanf(range,"%d-%d",&start,&end);
            strcat(response,"Accept-Ranges: bytes\r\n");
            strcat(response,"Content-Range: bytes ");
            sprintf(num_str,"%d-%d/%d",start,end,file_status.st_size);
            strcat(response,num_str);
            strcat(response,"\r\n");
        }
        total_len = end - start + 1;
        strcat(response,"Content-Length: ");
        sprintf(num_str,"%d",total_len);
        strcat(response, num_str);
        strcat(response,"\r\n");
    }
    strcat(response,"Server: HTTPS_SERVER\r\n");
    strcat(response,"Content-Type: ");
    strcat(response,filetype);
    log_header("[HTTPS response]:\n%s\n",response);
    strcat(response,"\r\n\r\n");
    if(cyc_SSL_send(ssl,response,strlen(response)) == -1)
        return;
    FILE* fp = fopen(filename,"rb");
    if(fp == NULL) return;
    fseek(fp,start,SEEK_SET);
    while(start <= end)
    {
        int read_len = fread(response,1,end - start + 1 < BUF_SIZE? end - start + 1:BUF_SIZE,fp);
        start = start + read_len;
        if(cyc_SSL_send(ssl,response,read_len) == -1)
            break;
    }
    fclose(fp);
    // int fd = open(filename,O_RDONLY);
    // if(fd < 0) return;
    // char* ptr = mmap(NULL,file_status.st_size, PROT_READ, MAP_SHARED, fd, 0);
    // cyc_SSL_send(ssl,ptr + start,total_len);
    // munmap(ptr,file_status.st_size);
    // close(fd);
}

void http_request_handler_func(void* args)
{
    int client_fd = (int)args;
    char buf[BUF_SIZE], method[BUF_SIZE],url[BUF_SIZE],version[BUF_SIZE],filename[BUF_SIZE],line[BUF_SIZE];
    char* host = NULL;
    int num;
    while (1) {
        num = cyc_recv(client_fd, buf, BUF_SIZE);
        if(num == -1)
            break;
        buf[num] = 0;
        log_header("\n[HTTP request]:\n%s",buf); 
        sscanf(buf, "%s %s %s", method, url, version);
        parse_host(buf, &host, line);
        if (strcmp(method, "GET") == 0 && strstr(version, "HTTP")) {
            parse_url(url, filename);   
            http_response(client_fd, filename,buf,host); //响应客户端
        }
        break;
    }
    close(client_fd); 
}

void https_request_handler_func(void* args)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings(); 
    const SSL_METHOD *ssl_method = TLS_server_method(); 
    SSL_CTX *ctx = SSL_CTX_new(ssl_method); 
    if(!ctx)
        err_message("SSL_CTX_new() error");
    // load certificate and private key 
    if(SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)
        err_message("cert error");
    if(SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)
        err_message("prikey error");
    if(SSL_CTX_check_private_key(ctx) <= 0)
        err_message("check private key error");

    //struct SSL_param* ssl_param = (struct SSL_param*)args;
    int client_fd = (int)args;
    SSL *ssl = SSL_new(ctx); 
    if(SSL_set_fd(ssl, client_fd) == 0){
        err_message("SSL_set_fd() error");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(client_fd); 
        return;
    }
    char buf[BUF_SIZE], method[BUF_SIZE],url[BUF_SIZE],version[BUF_SIZE],filename[BUF_SIZE], line[BUF_SIZE];
    char* range = NULL;
    int num;
    while ((num = SSL_accept(ssl))  <= 0) 
    {
        int ssl_err = SSL_get_error(ssl,num);
        if(num < 0 && ssl_err != SSL_CLIENT_HELLO_RETRY)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(client_fd); 
            return;
        }
    }
    while (1) {
        num = cyc_SSL_recv(ssl, buf, BUF_SIZE);
        if(num == -1)
            break;
        buf[num] = 0;
        log_header("\n[HTTPS request]:\n%s",buf);  
        sscanf(buf, "%s %s %s", method, url, version);
        parse_range(buf,&range, line);
        if (strcmp(method, "GET") == 0 && strstr(version, "HTTP")) {
            parse_url(url, filename);    //解析url，获取文件名
            https_response(ssl, filename, buf, range); //响应客户端
        }
        break;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(client_fd); 
}
void http_thread()
{
    int server_fd,client_fd;
    struct sockaddr_in server_addr,client_addr;
    unsigned client_addr_size,reuse = 1;

    server_fd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(HTTP_PORT);
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        err_message("HTTP setsockopt() error");
    if(bind(server_fd,(struct  sockaddr*)&server_addr,sizeof(server_addr)) == -1)
        err_message("HTTP bind() error");
    if(listen(server_fd,WAIT_QUEUE) == -1)
        err_message("HTTP listen() error");
    while(1)
    {
        pthread_t handler;
        client_addr_size = sizeof(client_addr);
        client_fd = accept(server_fd,(struct sockaddr*)&client_addr, &client_addr_size);
        if(client_fd == -1)
        {
            err_message("HTTP accept() error");
            continue;
        }
        //setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        pthread_create(&handler,NULL,(void*)http_request_handler_func,(void*)client_fd);
        pthread_detach(handler);
    }
    printf("HTTP thread exit\n");
    close(server_fd);
}
void https_thread()
{
    int server_fd,client_fd;
    struct sockaddr_in server_addr,client_addr;
    unsigned int client_addr_size,reuse = 1;

    server_fd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(HTTPS_PORT);
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        err_message("HTTPS setsockopt() error");
    if(bind(server_fd,(struct  sockaddr*)&server_addr,sizeof(server_addr)) == -1)
        err_message("HTTPS bind() error");
    if(listen(server_fd,WAIT_QUEUE) == -1)
        err_message("HTTPS listen() error");
    client_addr_size = sizeof(client_addr);
    while(1)
    {
        pthread_t handler;
        client_fd = accept(server_fd,(struct sockaddr*)&client_addr, &client_addr_size);
        if(client_fd == -1) 
        {
            err_message("HTTPS accept() error");
            continue;
        }
        //setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        pthread_create(&handler,NULL,(void*)https_request_handler_func,(void*)client_fd);
        pthread_detach(handler);  
    }
    printf("HTTPS thread exit\n");
    close(server_fd);  
}
int main(int argc, char* argv[])
{
    if(argc == 2 && strcmp(argv[1],"-v") == 0)
        print_log = 1;
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if(rc != 0)
        err_message("block signal error");
    pthread_t http_server,https_server;
    int ret;
    if((ret = pthread_create(&http_server,NULL,(void*)http_thread,NULL))!=0)
        err_message("http_server create error");
    if((ret = pthread_create(&https_server,NULL,(void*)https_thread,NULL))!=0)
        err_message("https_server create error");
    pthread_join(http_server,NULL);
    pthread_join(https_server,NULL);
    return 0;
} 
