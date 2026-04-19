# ChainGuard — Example Contracts

Use these contracts to demo ChainGuard during the hackathon.

## Vulnerable Contracts

| File | Vulnerability | SWC |
|------|--------------|-----|
| `ReentrancyVuln.sol` | External call before state update (TheDAO pattern) | SWC-107 |
| `TxOriginVuln.sol` | `tx.origin` used for ownership check | SWC-115 |
| `OverflowVuln.sol` | Integer arithmetic without SafeMath (`pragma ^0.7.0`) | SWC-101 |
| `UncheckedCallVuln.sol` | `.call()` return value silently discarded | SWC-104 |
| `SelfdestructVuln.sol` | `selfdestruct()` with no access modifier | SWC-106 |

## Safe Contracts

| File | Description |
|------|-------------|
| `SafeWallet.sol` | Reentrancy-safe wallet (CEI pattern + nonReentrant guard) |

## How to Use in the Demo

1. Copy the contents of any vulnerable contract
2. Paste into the ChainGuard editor
3. Click **Analyze**
4. The scanner will report the vulnerability, affected line, and recommended fix
