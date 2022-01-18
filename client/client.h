#pragma once
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstring>
#include <map>
#include <sstream>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


class Client
{
public:
    static const int BUFFER_SIZE = 4097;
private:
    int server_sock_desc;
    int my_sock_desc;
    int peer_sock_desc;

    char buffer[BUFFER_SIZE];
    std::string rcved_msg;


    sockaddr_in server_info;
    int server_port;
    std::string server_ip;

    sockaddr_in peer_info;
    int peer_port;
    std::string peer_ip;

    sockaddr_in client_info;
    int client_port;

    bool loop;

    fd_set fds;
    int maxfdp;
    timeval timeout;

    std::string username;
    int balance;
    int online_count;
    std::map<std::string, std::pair<std::string, std::string>> ip_table;

    pid_t pid;
    SSL_CTX* client_ctx;
    SSL_CTX* server_ctx;
    SSL* server_ssl;
    SSL* peer_ssl;
    RSA* privateKey;
public:
    Client(const std::string& server_ip, const int port);
    ~Client();
    void run();
private:
    void initClientCTX();
    void initServerCTX();
    void loadCert(std::string certfile, std::string keyfile);
    void showCert(SSL* ssl);
    void createMySocket();
    void sendMessage(SSL* ssl, const std::string msg);
    void rcvMessage(SSL* ssl);
    void reg();
    void login();
    void list();
    void transaction();
    void endClient();
    void makeIPtable();
    void printMenu();
};