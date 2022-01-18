#include "server.h"

Server::Server(std::string port) : server_port(std::stoi(port)), addrlen(sizeof(this->server_info)), stopped(false), connection_count(0)
{
    system("yes '' | openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout a.key -out a.crt");
    this->initServerCTX();
    this->loadCert("a.crt", "a.key");
    this->initListenSocket();
    for(int i = 0; i < this->MAX_THREADS; i++)
    {
        this->threadPool.emplace_back(&Server::runThread, this);
    }
}

Server::~Server()
{
    this->shutdown();
}

void Server::run()
{
    while(!stopped)
    {
        Connection* clientConnection = new Connection;
        int client_socket_desc = accept(this->listen_sock_desc, (sockaddr*)&clientConnection->client_addr, (socklen_t*)&this->addrlen);
        char clientIP[20];
        inet_ntop(AF_INET, &clientConnection->client_addr.sin_addr, clientIP, (int)clientConnection->client_addr.sin_port);
        SSL* ssl = SSL_new(this->ctx);
        SSL_set_fd(ssl, client_socket_desc);
        clientConnection->ssl = ssl;
        clientConnection->sockfd = client_socket_desc;
        clientConnection->ip = clientIP;
        clientConnection->port = std::to_string((int)clientConnection->client_addr.sin_port);
        if (SSL_accept(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            close(client_socket_desc);
            continue;
        }
        if(client_socket_desc > 0)
        {
            if(connection_count < Server::MAX_THREADS)
            {
                connection_count++;
                
                std::cout << "Connection from " + clientConnection->ip + ":" + clientConnection->port + " established\n";
                this->connection_queue.push(clientConnection);
            }
            else
            {
                this->sendMessage(clientConnection, "Reached maximum connections\n");
                close(client_socket_desc);
            }
        }
        
    }
}

void Server::sendMessage(Connection* clientConnection, const std::string message)
{
    std::cout << "Sending: " + message + '\n';
    if(SSL_write(clientConnection->ssl, message.c_str(), message.size()) < 0)
    {
        std::cerr << "Failed to send message\n";
    }
}

std::string Server::receiveMessage(Connection* clientConnection)
{
    char buffer[Server::BUFFER_LEN]= {0};
    std::string msg;
    if(SSL_read(clientConnection->ssl, buffer, sizeof(buffer)) <= 0)
    {
        std::cout << "Socket closed\n";
        this->handleExit(clientConnection);
    }
    else
    {
        msg = buffer;
    }
    return msg;
}

void Server::initListenSocket()
{
    this->listen_sock_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(this->listen_sock_desc < 0){
        std::cerr << "Listen socket creation failure\n";
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if(setsockopt(this->listen_sock_desc, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0)
    {
        std::cerr << "Set listen socket option failed\n";
        exit(EXIT_FAILURE);
    }

    this->server_info.sin_family = AF_INET;
    this->server_info.sin_addr.s_addr = INADDR_ANY;
    this->server_info.sin_port = htons(this->server_port);

    if (bind(this->listen_sock_desc, (struct sockaddr *)&this->server_info, sizeof(this->server_info)) < 0)  
    {  
        std::cerr << "Listen socket bind failed\n";
        exit(EXIT_FAILURE);  
    }

    if(listen(this->listen_sock_desc, 3) < 0)
    {
        std::cerr << "Listen failure\n";
    }

    std::cout << "Waiting for connections on port: " + std::to_string(this->server_port) + "\n";
}

void Server::initServerCTX()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    this->ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
}   

void Server::loadCert(std::string certfile, std::string keyfile)
{
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if ( SSL_CTX_use_certificate_file(this->ctx, certfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(this->ctx, keyfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(this->ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void Server::runThread()
{
    while(!stopped)
    {
        this->queue_mutex.lock();
        if(this->connection_queue.size() == 0)
        {
            this->queue_mutex.unlock();
            continue;
        }
        Connection* clientConnection = this->connection_queue.front();
        this->connection_queue.pop();
        this->queue_mutex.unlock();
        this->handleConnection(clientConnection);
    }
}

void Server::handleConnection(Connection* clientConnection)
{
    char buffer[Server::BUFFER_LEN];
    this->sendMessage(clientConnection, "Hello\n");
    while(true)
    {
        memset(buffer, 0, sizeof(buffer));
        if(SSL_read(clientConnection->ssl, buffer, sizeof(buffer)) <= 0)
        {
            std::cout << "Connection closed\n";
            this->handleExit(clientConnection);
            break;
        }
        std::string rcvedMessage = buffer;
        std::cout << "Received: \n" + rcvedMessage + "\n";
        if(rcvedMessage.substr(0, 8) == "REGISTER")
        {
            this->handleRegister(clientConnection, rcvedMessage);
        }
        else if(rcvedMessage.substr(0, 4) == "List")
        {
            this->handleList(clientConnection);
        }
        else if(rcvedMessage.substr(0, 4) == "Exit")
        {
            this->handleExit(clientConnection);
        }
        else
        {
            int bangs = std::count(rcvedMessage.begin(), rcvedMessage.end(), '#');
            if(bangs == 1)
            {
                this->handleLogin(clientConnection, rcvedMessage);
            }
            else if(bangs == 2)
            {
                this->handleTransaction(clientConnection, rcvedMessage);
            }
            else
            {
                std::cerr << "Unrecognized request format\n";
            }
        }
    }
    SSL_shutdown(clientConnection->ssl);
    SSL_free(clientConnection->ssl);
    close(clientConnection->sockfd);
    this->connection_count--;
    delete clientConnection;
}

void Server::shutdown()
{
    this->stopped = true;
    this->online.clear();
    for(auto& thread : this->threadPool)
    {
        thread.join();
    }
}

void Server::handleRegister(Connection* clientConnection, std::string msg)
{
    int bashLoc = msg.find('#');
    std::string username = msg.substr(bashLoc + 1, msg.size() - bashLoc - 1);
    if(this->accounts.find(username) != this->accounts.end())
    {
        char buffer[Server::BUFFER_LEN] = "210 FAIL\n";
        std::cout << "Existing account " + username + "\n";
        this->sendMessage(clientConnection, "210 FAIL\n");
    }
    else
    {
        this->accounts[username] = { username, 10000 };
        std::cout << "Account \"" + username + "\" registered\n";
        this->sendMessage(clientConnection, "100 OK\n");
    }
}

void Server::handleLogin(Connection* clientConnection, std::string msg)
{
    int bashLoc = msg.find('#');
    std::string username = msg.substr(0, bashLoc);
    std::string port = msg.substr(bashLoc + 1, msg.size() - bashLoc - 1);
    if(!clientConnection->username.empty())
    {
        std::cout << "Client already logged in\n";
        this->sendMessage(clientConnection, "220 AUTH_FAIL\n");
    }
    else if(this->online.find(username) != this->online.end())
    {
        std::cout << "Account " + username + " is already logged in\n";
        this->sendMessage(clientConnection, "220 AUTH_FAIL\n");
    }
    else if(this->accounts.find(username) == this->accounts.end())
    {
        std::cout << "Account not registered\n";
        this->sendMessage(clientConnection, "220 AUTH_FAIL\n");
    }
    else
    {
        std::cout << "Account " + username + " logged in using " + clientConnection->ip + ":" + port + "\n";
        clientConnection->username = username;
        this->online[username] = std::make_pair(clientConnection->ip, port);
        this->connections[username] = clientConnection;
        this->sendMessage(clientConnection, this->makeList(clientConnection));
    }
}

std::string Server::makeList(Connection* clientConnection)
{
    std::string listStr = std::to_string(this->accounts[clientConnection->username].balance) + "\npublic key\n" + std::to_string(this->online.size()) + "\n";
    for(auto& it : this->online)
    {
        listStr += it.first + "#" + it.second.first + "#" + it.second.second + "\n";
    }
    return listStr;
}

void Server::handleList(Connection* clientConnection)
{
    if(clientConnection->username.empty())
    {
        this->sendMessage(clientConnection, "Please login first\n");
        return;
    }
    this->sendMessage(clientConnection, this->makeList(clientConnection));
}

void Server::handleExit(Connection* clientConnection)
{
    // std::cout << "Handling Exit\n";
    // std::cout << "Removing records of " + clientConnection->username + "\n";
    if(this->online.find(clientConnection->username) != this->online.end())
    {
        this->online.erase(this->online.find(clientConnection->username));
    }
    if(this->connections.find(clientConnection->username) != this->connections.end())
    {
        this->connections.erase(this->connections.find(clientConnection->username));
    }
}

void Server::handleTransaction(Connection* clientConnection, std::string msg)
{
    int bashLoc1 = msg.find("#");
    int bashLoc2 = msg.find("#", bashLoc1 + 1);
    Account* payer = &this->accounts[msg.substr(0, bashLoc1)];
    int amount = std::stoi(msg.substr(bashLoc1 + 1, bashLoc2 - bashLoc1 - 1));
    Account* payee = &this->accounts[msg.substr(bashLoc2 + 1, msg.size() - bashLoc2 - 1)];
    std::cout << "Transferring " + std::to_string(amount) + " from " + payer->username + " to " + payee->username + "\n";
    if(payee->username != clientConnection->username)
    {
        std::cout << "Message comming from wrong client\n";

        this->sendMessage(this->connections[payer->username], "Transfer Fail!\n");
    }
    else if(payer->balance < amount)
    {
        std::cout << "Payer does not have sufficient money!\n";
        this->sendMessage(this->connections[payer->username], "Transfer Fail!\n");
    }
    else if(amount < 0)
    {
        std::cout << "Transaction not legal\n";
        this->sendMessage(this->connections[payer->username], "Transfer Fail!\n");
    }
    else
    {
        payer->balance -= amount;
        payee->balance += amount;
        this->sendMessage(this->connections[payer->username], "Transfer OK!\n");
    }
}