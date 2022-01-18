#include <signal.h>
#include <functional>
#include "server.h"

Server* serverptr = nullptr;


int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        std::cerr << "Not enough arguments" << std::endl;
        exit(1);
    }
    Server server(argv[1]);
    server.run();
    return 0;
}