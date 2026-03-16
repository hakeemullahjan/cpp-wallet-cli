#include "wallet.h"
#include <iostream>
#include <cstring>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <command> [args]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  create   Create a new wallet\n";
    std::cout << "  address  Show wallet address\n";
    std::cout << "  balance  Show native balance for a network\n";
    std::cout << "  send     Send native token: send <network> <to> <amount>\n";
    std::cout << "  networks List supported networks\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "create") == 0) {
        createWallet();
    } else if (strcmp(command, "address") == 0) {
        showAddress();
    } else if (strcmp(command, "balance") == 0) {
        if (argc < 3) {
            std::cerr << "Missing network name. Example: " << argv[0] << " balance eth-sepolia\n\n";
            listSupportedNetworks();
            return 1;
        }
        showBalance(argv[2]);
    } else if (strcmp(command, "send") == 0) {
        if (argc < 5) {
            std::cerr << "Usage: " << argv[0] << " send <network> <to> <amount>\n";
            std::cerr << "Example: " << argv[0] << " send eth-sepolia 0xabc... 0.01\n\n";
            listSupportedNetworks();
            return 1;
        }
        sendNative(argv[2], argv[3], argv[4]);
    } else if (strcmp(command, "networks") == 0) {
        listSupportedNetworks();
    } else {
        std::cerr << "Unknown command: " << command << "\n\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
