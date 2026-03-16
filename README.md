# cpp-wallet-cli

Simple C++ EVM wallet CLI using `secp256k1` keys and Keccak-256 address derivation.

## Supported networks

- `eth-sepolia` (aliases: `ethereum`, `sepolia`, `eth`)
- `bsc-testnet` (aliases: `binance`, `bsc`, `bnb`)
- `polygon-amoy` (aliases: `polygon`, `amoy`, `matic`)

## Commands

- `./wallet create`
- `./wallet address`
- `./wallet networks`
- `./wallet balance <network>`
- `./wallet send <network> <to> <amount>`

Examples:

- `./wallet balance eth-sepolia`
- `./wallet balance bsc`
- `./wallet balance polygon`
- `./wallet send eth-sepolia 0x1111111111111111111111111111111111111111 0.01`
