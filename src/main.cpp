#include "wallet.h"
#include <iostream>
#include <cstring>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <command>\n\n";
    std::cout << "Commands:\n";
    std::cout << "  create   Create a new wallet\n";
    std::cout << "  address  Show wallet address\n";
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
    } else {
        std::cerr << "Unknown command: " << command << "\n\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}
