#ifndef WALLET_H
#define WALLET_H

#include <string>

void createWallet();
void showAddress();
void showBalance(const std::string& networkName);
void sendNative(const std::string& networkName, const std::string& toAddress, const std::string& amountNative);
void listSupportedNetworks();

#endif // WALLET_H
