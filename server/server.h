#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <algorithm>
#include <map>
#include <utility>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <random>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

struct Account
{
    std::string username;
    int balance;
};

struct Connection
{
    SSL* ssl;
    int sockfd;
    sockaddr_in client_addr;
    std::string ip;
    std::string port;
    std::string username;
};


class Server
{
public:
    bool stopped;
private:
    static const int MAX_THREADS = 3;
    static const int BUFFER_LEN = 1025;

    std::mutex queue_mutex;
    std::queue<Connection*> connection_queue;

    int connection_count;

    int listen_sock_desc;

    std::vector<std::thread> threadPool;

    sockaddr_in server_info;
    int addrlen;
    int server_port;

    std::map<std::string, Connection*> connections;
    std::map<std::string, Account> accounts;
    std::map<std::string, std::pair<std::string, std::string>> online; //<username, <ip, port>>

    SSL_CTX* ctx;
public:
    Server(std::string port);
    ~Server();
    void run();
private:
    void sendMessage(Connection* clientConnection, const std::string message);
    std::string receiveMessage(Connection* clientConnection);
    void initListenSocket();
    void initServerCTX();
    void loadCert(std::string certfile, std::string keyfile);
    void runThread();
    void handleConnection(Connection* clientConnection);
    void shutdown();
    void handleRegister(Connection* clientConnection, std::string msg);
    void handleLogin(Connection* clientConnection, std::string msg);
    std::string makeList(Connection* clientConnection);
    void handleList(Connection* clientConnection);
    void handleExit(Connection* clientConnection);
    void handleTransaction(Connection* clientConnection, std::string msg);
};