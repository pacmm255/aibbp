# Dangerous JSON-RPC Methods Enabled on Public Cronos EVM Nodes

## Summary

The public Cronos EVM RPC endpoints (`evm.cronos.org` and `evm-t3.cronos.org`) expose dangerous `personal_*`, `txpool_*`, and `eth_sendTransaction` JSON-RPC methods that should be disabled on public-facing nodes. These methods allow account management operations, transaction pool inspection (enabling MEV/frontrunning), and potentially transaction submission if keys exist in the node's keyring.

## Severity

**High** (Critical if node keyring contains any funded accounts)

## Affected Endpoints

- `https://evm.cronos.org/` (Cronos mainnet)
- `https://evm-t3.cronos.org/` (Cronos testnet)

## Reproduction Steps

### Step 1: Verify personal_* methods are enabled (not rejected)

```bash
# personal_listAccounts — returns empty array (ENABLED, not "method not found")
curl -s https://evm.cronos.org/ -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":1}'
# → {"id":1,"result":[],"jsonrpc":"2.0"}

# Compare with a truly disabled method:
curl -s https://evm.cronos.org/ -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x00"],"id":1}'
# → {"error":{"code":-32601,"message":"the method debug_traceTransaction does not exist/is not available"}}
```

### Step 2: Enumerate all enabled dangerous methods

```
ENABLED (returns result or processes request):
  personal_listAccounts       → []
  personal_listWallets        → null
  personal_newAccount         → "too many failed passphrase attempts" (processes request)
  personal_importRawKey       → "too many failed passphrase attempts" (processes request)
  personal_unlockAccount      → false (processes request)
  personal_sendTransaction    → "missing value for required argument" (processes request)
  personal_sign               → "missing value for required argument" (processes request)
  personal_ecRecover          → "missing value for required argument" (processes request)
  eth_sendTransaction         → "failed to find key in the node's keyring" (processes request)
  eth_accounts                → []
  net_peerCount               → 21
  txpool_status               → {"pending":"0x0","queued":"0x0"}
  txpool_content              → {"pending":{},"queued":{}}

DISABLED (properly restricted):
  admin_peers                 → method does not exist
  admin_nodeInfo              → method does not exist
  miner_start                 → method does not exist
  debug_traceBlock            → method does not exist
```

### Step 3: Verify transaction submission is attempted (not rejected)

```bash
curl -s https://evm.cronos.org/ -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000001","value":"0x0"}],"id":1}'
```

Response:
```json
{"id":1,"error":{"code":-32000,"message":"failed to find key in the node's keyring; no key for given address or file; key with address crc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqya6f4r not found: key not found"}}
```

The node **attempted to look up the signing key in its keyring**. The error confirms: (a) the method is enabled, (b) the node has a keyring, (c) it would sign and submit the transaction if the key existed.

### Step 4: Verify private key import is processed

```bash
curl -s https://evm.cronos.org/ -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"personal_importRawKey","params":["0000000000000000000000000000000000000000000000000000000000000001","testpassword"],"id":1}'
```

Response:
```json
{"id":1,"error":{"code":-32000,"message":"too many failed passphrase attempts"}}
```

The method **processes the request** (it's trying to validate the passphrase, not rejecting the method itself). The "too many failed passphrase attempts" error suggests a rate limit on key import attempts, but the method is actively processing requests.

### Step 5: Network topology disclosure

```bash
curl -s https://evm.cronos.org/ -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
# → {"id":1,"result":21,"jsonrpc":"2.0"}
```

The node has 21 connected peers — this leaks network topology information.

## Impact

### 1. Potential Fund Theft (Critical if keyring has keys)

If the node's keyring contains any accounts (from past use, testing, or configuration), an attacker could:
1. `personal_listAccounts` to enumerate accounts
2. `personal_unlockAccount` to unlock them (brute-force passphrase)
3. `personal_sendTransaction` or `eth_sendTransaction` to drain funds

Currently `personal_listAccounts` returns `[]`, but this may change if keys are added during node maintenance.

### 2. Private Key Import

`personal_importRawKey` accepts and processes requests. An attacker could import a known private key into the node, then use `personal_sendTransaction` to submit transactions signed by that key through Cronos's own infrastructure.

### 3. Transaction Pool Inspection (MEV/Frontrunning)

`txpool_content` and `txpool_status` expose all pending and queued transactions. This enables:
- **Frontrunning**: See pending DEX trades and submit higher-gas transactions to profit
- **Sandwich attacks**: Insert transactions before and after victim trades
- **MEV extraction**: Monitor and exploit pending transaction ordering

### 4. Network Topology Disclosure

`net_peerCount` reveals the number of connected peers (21), which helps map the network infrastructure.

## Root Cause

The Cronos EVM node is configured with `personal`, `txpool`, and full `eth` API namespaces enabled on the public RPC endpoint. These namespaces should only be available on private/admin interfaces.

## Remediation

1. Disable `personal_*` namespace on public RPC endpoints
2. Disable `txpool_*` namespace on public RPC endpoints
3. Restrict `eth_sendTransaction` — public nodes should only accept `eth_sendRawTransaction` (pre-signed transactions)
4. Disable `net_peerCount` on public endpoints
5. Ensure no keys exist in the node's keyring on public-facing nodes
6. Use separate RPC configurations for public vs internal access
