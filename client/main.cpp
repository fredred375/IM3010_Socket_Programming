#include "client.h"

int main(int argc, char* argv[]) //argv[1] = server_info ip, argv[2] = server_info port
{
	Client client(argv[1], atoi(argv[2]));
	client.run();
	return 0;
}