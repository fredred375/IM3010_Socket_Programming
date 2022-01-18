#include "client.h"

Client::Client(const std::string& server_ip, const int server_port) :
    server_ip(server_ip), server_port(server_port), loop(true), timeout{0, 0}
{
    this->pid = getpid();
    char command[100];
    sprintf(command, "yes '' | openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout ./keys/%d.key -out ./keys/%d.crt", this->pid, this->pid);
    system(command);

    FILE* keyfile = fopen(("./keys/" + std::to_string(this->pid) + ".key").c_str(), "r");

    this->privateKey = PEM_read_RSAPrivateKey(keyfile, nullptr, nullptr, nullptr);

    fclose(keyfile);

    this->initClientCTX();
    this->initServerCTX();
    this->loadCert("./keys/" + std::to_string(this->pid) + ".crt", "./keys/" + std::to_string(this->pid) + ".key");

    this->server_sock_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    if(this->server_sock_desc < 0)
    {
        std::cout << "Server socket creation failed" << std::endl;
        exit(1);
    }

    this->server_info.sin_family = AF_INET;
    this->server_info.sin_port = htons(server_port);
    
    if(inet_pton(AF_INET, this->server_ip.c_str(), &this->server_info.sin_addr) < 0)
    {
        std::cout << "Invalid IP address/ IP Address not supported" << std::endl;
        exit(1);
    }
    if(connect(this->server_sock_desc, (sockaddr *)&this->server_info, sizeof(this->server_info)) < 0)
    {
        std::cout << "Socket connection failed" << std::endl;
        exit(1);
    }
    std::cout << "Client connected to server" << std::endl;

    this->server_ssl = SSL_new(this->client_ctx);
    SSL_set_fd(this->server_ssl, this->server_sock_desc);
    if (SSL_connect(this->server_ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        std::cout << "Connected with " << SSL_get_cipher(this->server_ssl) << " encryption\n";
        this->showCert(this->server_ssl);
    }

    this->createMySocket();

    this->maxfdp = (this->my_sock_desc > fileno(stdin)) ? this->my_sock_desc : fileno(stdin);
    this->maxfdp = (this->maxfdp > this->server_sock_desc) ? this->maxfdp + 1 : this->server_sock_desc + 1;
}

Client::~Client()
{
    close(this->server_sock_desc);
    SSL_shutdown(this->server_ssl);
    SSL_free(this->server_ssl);
    
    SSL_CTX_free(this->server_ctx);
    SSL_CTX_free(this->client_ctx);
}

void Client::run()
{
    this->printMenu();
    while(this->loop)
    {
        FD_ZERO(&this->fds);
        FD_SET(this->my_sock_desc, &this->fds);
        FD_SET(this->server_sock_desc, &this->fds);
        FD_SET(fileno(stdin), &this->fds);
        switch(select(this->maxfdp, &this->fds, NULL, NULL, &this->timeout))
        {
            case -1:
                this->endClient();
                break;
            case 0:
                break;
            default:
                if(FD_ISSET(this->server_sock_desc, &this->fds))
                {
                    std::string message;
                    // std::cout << "Server socket received message" << std::endl;
                    // memset(this->buffer, 0, sizeof(this->buffer));
                    // recv(this->server_sock_desc, buffer, sizeof(buffer), 0);
                    // message = buffer;
                    // std::cout << message << std::endl;
                    this->rcvMessage(this->server_ssl);
                    
                    if(this->rcved_msg == "Transfer OK!\n")
                    {
                        // std::cout << "------------------" << std::endl;
                        std::cout << "Transaction successful!" << std::endl;
                        std::cout << "Update list" << std::endl;
                        this->list();
                        // std::cout << "------------------" << std::endl;
                    }
                    else if(this->rcved_msg == "Transfer Fail!\n")
                    {
                        std::cout << "Transaction failed!" << std::endl;
                    }
                }
                else if(FD_ISSET(this->my_sock_desc, &this->fds))
                {
                    std::string message;
                    // std::cout << "My socket received message" << std::endl;
                    socklen_t addr_len = sizeof(this->peer_info);
                    this->peer_sock_desc = accept(this->my_sock_desc, (sockaddr*)&this->peer_info, &addr_len);
                    SSL* ssl = SSL_new(this->server_ctx);
                    SSL_set_fd(ssl, peer_sock_desc);
                    if (SSL_accept(ssl) == -1)
                    {
                        ERR_print_errors_fp(stderr);
                        close(peer_sock_desc);
                        continue;
                    }
                    this->rcvMessage(ssl);
                    //parse a#100#b
                    unsigned char cipher[4097], plain[4097];
                    memcpy(cipher, buffer, sizeof(buffer));
                    // std::cout << this->rcved_msg << std::endl;
                    // RSA_print_fp(stdout, this->privateKey, 0);
                    RSA_private_decrypt(RSA_size(this->privateKey), cipher, plain, this->privateKey, RSA_PKCS1_PADDING);
                    this->rcved_msg = reinterpret_cast<char*>(plain);
                    int pos1 = this->rcved_msg.find('#');
                    int pos2 = this->rcved_msg.find('#', pos1 + 1);
                    std::cout << this->rcved_msg.substr(pos2 + 1, this->rcved_msg.size() - pos2 - 1) << std::endl;
                    if(this->rcved_msg.substr(pos2 + 1, this->rcved_msg.size() - pos2 - 1) == this->username)
                    {
                        std::cout << "------------------" << std::endl;
                        std::cout << "Recieved transaction from " << this->rcved_msg.substr(0, pos1) << std::endl;
                        std::cout << "Amount: " << this->rcved_msg.substr(pos1 + 1, pos2 - pos1 - 1) << std::endl;
                        this->sendMessage(this->server_ssl, rcved_msg);
                        std::cout << "------------------" << std::endl;
                    }
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                }
                else if(FD_ISSET(fileno(stdin), &this->fds))
                {
                    std::string command;
                    std::cin >> command;
                    fflush(stdout);
                    if(command == "Login")
                    {
                        this->login();
                    }
                    else if(command == "Register")
                    {
                        this->reg();
                    }
                    else if(command == "List")
                    {
                        this->list();
                    }
                    else if(command == "Transaction")
                    {
                        this->transaction();
                    }
                    else if(command == "Exit")
                    {
                        this->endClient();
                    }
                    else if(command == "Menu")
                    {
                        this->printMenu();
                    }
                    else
                    {
                        std::cout << "Command not found\n" << std::endl;
                    }
                }
                break;
        }
    }
}

void Client::initClientCTX()
{
    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    this->client_ctx = SSL_CTX_new(SSLv23_client_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (this->client_ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
}

void Client::initServerCTX()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    this->server_ctx = SSL_CTX_new(SSLv23_server_method());
    if (server_ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        abort();
    }
}

void Client::loadCert(std::string certfile, std::string keyfile)
{
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if ( SSL_CTX_use_certificate_file(this->client_ctx, certfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(this->client_ctx, keyfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(this->client_ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    if ( SSL_CTX_use_certificate_file(this->server_ctx, certfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 載入使用者私鑰 */
    if ( SSL_CTX_use_PrivateKey_file(this->server_ctx, keyfile.c_str(), SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* 檢查使用者私鑰是否正確 */
    if ( !SSL_CTX_check_private_key(this->server_ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void Client::showCert(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        std::cout << "Digital certificate information:\n";
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::cout << "Certificate: " << line << std::endl;
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::cout << "Issuer: " << line << std::endl;
        free(line);
        X509_free(cert);
    }
    else
        std::cout << "No certificate information!\n";
}

void Client::createMySocket()
{
    this->my_sock_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(this->my_sock_desc < 0)
    {
        std::cout << "My socket creation failed" << std::endl;
        exit(1);
    }
}

void Client::sendMessage(SSL* ssl, std::string msg)
{
    if(SSL_write(ssl, msg.c_str(), msg.length()) < 0)
    {
        std::cout << "Failed to send message" << std::endl;
        return;
    }
    // std::cout << "Message: \"" << msg << "\" sent" << std::endl; 
}

void Client::rcvMessage(SSL* ssl)
{
    memset(this->buffer, 0, sizeof(this->buffer));
    if(SSL_read(ssl, this->buffer, sizeof(this->buffer)) > 0)
    {
        this->rcved_msg = this->buffer;
        // std::cout << "Received message: \n\"" << this->buffer << "\"" << std::endl;
    }
    else
    {
        std::cout << "Socket closed" << std::endl;
        this->endClient();
    }
    
}

void Client::reg()
{
    std::cout << "------------------" << std::endl;
    std::string username;
    std::cout << "Username: ";
    std::cin >> username;
    sendMessage(this->server_ssl, "REGISTER#" + username);
    rcvMessage(this->server_ssl);
    if(this->rcved_msg == "100 OK\n")
    {
        std::cout << "User " << username << " registered!" << std::endl;
    }
    else
    {
        std::cout << this->rcved_msg << std::endl;
        std::cout << "User already registered" << std::endl;
    }
    std::cout << "------------------" << std::endl;
}

void Client::login()
{
    std::cout << "------------------" << std::endl;

    std::string username;
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << "Port: ";
    std::cin >> this->client_port;
    while(this->client_port < 1024 || this->client_port > 65535)
    {
        std::cout << "Please enter a valid port(1024~65535)" << std::endl;
        std::cout << "Port: ";
        std::cin >> this->client_port;
    }
    this->client_info.sin_family = AF_INET;
    this->client_info.sin_addr.s_addr = INADDR_ANY;
    this->client_info.sin_port = htons(this->client_port);
    
    if(bind(my_sock_desc,  (struct sockaddr *)&this->client_info, sizeof(this->client_info)) < 0)
    {
        std::cout << "Binding failed, maybe port is already in use" << std::endl;
        std::cout << "Login failed" << std::endl;
        this->createMySocket();
    }
    else{
        sendMessage(this->server_ssl, username + "#" + std::to_string(this->client_port));
        rcvMessage(this->server_ssl);
        if(rcved_msg != "220 AUTH_FAIL\n")
        {
            this->makeIPtable();
            this->username = username;
            listen(this->my_sock_desc, 1);
            // std::cout << "Peer listening on port " << this->client_port << std::endl;
            std::cout << "You are now logged in as user " << this->username << std::endl;
        }
        else
        {
            std::cout << "Login failed" << std::endl;
        }
    }
    std::cout << "------------------" << std::endl;
}

void Client::list()
{
    std::cout << "------------------" << std::endl;
    sendMessage(this->server_ssl, "List");
    rcvMessage(this->server_ssl);
    if(!rcved_msg.empty() && rcved_msg != "Please login first\n")
    {
        this->makeIPtable();
        std::cout << "Your balance: " << this->balance << std::endl;
        std::cout << "Online users: " << std::endl;
        for(auto it : this->ip_table)
        {
            std::cout << it.first << "(" << it.second.first << ":" << it.second.second << ")" << std::endl;
        }
    }
    else
    {
        std::cout << "You are not logged in" << std::endl;
    }
    std::cout << "------------------" << std::endl;
}

void Client::transaction()
{
    std::cout << "------------------" << std::endl;
    std::string dest;
    int amount;
    std::cout << "Destination account: ";
    std::cin >> dest;
    if(this->ip_table.count(dest) == 0)
    {
        std::cout << "Account not found" << std::endl;
        return;
    }
    else
    {
        this->peer_ip = this->ip_table[dest].first;
        this->peer_port = std::stoi(this->ip_table[dest].second);
    }
    std::cout << "Amount: ";
    std::cin >> amount;

    this->peer_sock_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(this->peer_sock_desc < 0)
    {
        std::cout << "Peer Socket creation failed" << std::endl;
        return;
    }
    this->peer_info.sin_family = AF_INET;
    this->peer_info.sin_port = htons(peer_port);
    if(inet_pton(AF_INET, this->peer_ip.c_str(), &this->peer_info.sin_addr) < 0)
    {
        std::cout << "Invalid IP address/ IP Address not supported" << std::endl;
        return;
    }
    if(connect(this->peer_sock_desc, (sockaddr *)&this->peer_info, sizeof(this->peer_info)) < 0)
    {
        std::cout << " Peer socket connection failed" << std::endl;
        return;
    }
    // std::cout << "Peer socket connected" << std::endl;
    this->peer_ssl = SSL_new(this->client_ctx);
    SSL_set_fd(this->peer_ssl, this->peer_sock_desc);
    if (SSL_connect(this->peer_ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        std::cout << "Connected with " << SSL_get_cipher(this->peer_ssl) << " encryption\n";
        this->showCert(this->peer_ssl);
    }
    X509* peer_cert = SSL_get_peer_certificate(this->peer_ssl);
    // PEM_write_X509(stdout, peer_cert);
    EVP_PKEY* public_key = X509_get_pubkey(peer_cert);
    RSA* rsa_key = EVP_PKEY_get1_RSA(public_key);
    std::string message = this->username + "#" + std::to_string(amount) + "#" + dest;
    unsigned char* plain = (unsigned char *)&message[0];
    unsigned char cipher[4097];
    RSA_public_encrypt(message.length() + 1, plain, cipher, rsa_key, RSA_PKCS1_PADDING);
    if(SSL_write(this->peer_ssl, cipher, sizeof(cipher)) < 0)
    {
        std::cout << "Failed to send message" << std::endl;
        return;
    }
    std::cout << "------------------" << std::endl;
    SSL_free(peer_ssl);
}

void Client::endClient()
{
    std::cout << "------------------" << std::endl;
    sendMessage(this->server_ssl, "Exit");
    std::cout << "Bye" << std::endl;
    std::cout << "------------------" << std::endl;
    exit(0);
}

void Client::makeIPtable()
{
    this->ip_table.clear();
    std::istringstream iss(rcved_msg);
    std::string line;
    std::getline(iss, line);
    this->balance = std::stoi(line);
    std::getline(iss, line);
    std::getline(iss, line);
    this->online_count = std::stoi(line);
    while(std::getline(iss, line))
    {
        int pos1 = line.find('#');
        int pos2 = line.find('#', pos1 + 1);
        this->ip_table[line.substr(0, pos1)] = std::make_pair(line.substr(pos1 + 1, pos2 - pos1 - 1), line.substr(pos2 + 1, line.length() - pos2 - 1));
    }
}

void Client::printMenu()
{
    std::cout << "Commands:" << std::endl;
    std::cout << "------------------" << std::endl;
    std::cout << "Register" << std::endl;
    std::cout << "Login" << std::endl;
    std::cout << "List" << std::endl;
    std::cout << "Transaction" << std::endl;
    std::cout << "Exit" << std::endl;
    std::cout << "Menu" << std::endl;
    std::cout << "------------------" << std::endl;
}