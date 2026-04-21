# Title (copy in Cantina "Title" field)

OndoOracle Missing Staleness Validation — Inconsistent With All Other Push-Based Oracle Adapters

# Severity (select in Cantina)

Medium

# Description (copy in Cantina "Description" field — full markdown body below)

## Summary

The `OndoOracle` adapter at `euler-price-oracle/src/adapter/ondo/OndoOracle.sol:41-45` calls `IOndoRWAOracle(rwaOracle).getPrice()` without any staleness validation. This is inconsistent with every other push-based adapter in the Euler price oracle system, each of which enforces a `maxStaleness` bound. A stale RWA NAV price accepted as collateral value can cause over-borrowing, delayed liquidations, and arbitrage against the actual off-chain market price.

## Vulnerability

### Code reference

```solidity
// euler-price-oracle/src/adapter/ondo/OndoOracle.sol:41-45
function _getQuote(uint256 inAmount, address, address) internal view override returns (uint256) {
    uint256 price = IOndoRWAOracle(rwaOracle).getPrice();
    // NO staleness validation — price could be hours/days old
    return inAmount * price / 10 ** decimals;
}
```

### Consistency gap with sibling adapters

| Adapter | Staleness check | Max staleness bound |
|---------|-----------------|---------------------|
| `ChainlinkOracle` | `block.timestamp - updatedAt > maxStaleness` | 1 min – 72 h |
| `ChronicleOracle` | `block.timestamp - age > maxStaleness` | 1 min – 72 h |
| `PythOracle` | `block.timestamp - publishTime > maxStaleness` | 0 – 15 min |
| `RedstoneCoreOracle` | `block.timestamp - priceTimestamp > maxStaleness` | 0 – 5 min |
| **`OndoOracle`** | **None** | **N/A** |

Every other push-based adapter bounds the allowed staleness window via a `maxStaleness` parameter. `OndoOracle` accepts `getPrice()` unconditionally.

## Root Cause

`OndoOracle._getQuote` does not read a timestamp from the Ondo RWA oracle and does not compare it to `block.timestamp - maxStaleness`. The adapter stores no `maxStaleness` parameter, so no bound can be enforced even if a timestamp were introduced.

## Attack Path

Ondo RWA oracles price real-world assets (USDY, OUSG). NAV updates can be infrequent or delayed due to:
- Weekends / holidays (off-chain markets closed)
- Operator downtime or upstream pricing source outages
- Intentional delay between NAV computation and on-chain publication

A stale NAV accepted as a collateral price leads to three concrete attacker/user behaviours:

1. **Over-borrowing during RWA depreciation**: Underlying asset depreciates off-chain, but the on-chain oracle still reports yesterday's higher NAV. A borrower can draw down additional debt against collateral that is no longer worth the reported value.
2. **Delayed liquidations**: When a holder's collateral has actually lost value, the oracle keeps reporting the previous value, so health factor computations stay above the liquidation threshold. Bad debt accumulates until the oracle is manually refreshed.
3. **Oracle-vs-market arbitrage**: A holder observes a stale price that does not match the actual off-chain NAV and either opens new positions or exits existing ones at a stale favorable rate before the oracle catches up.

## Impact

Medium. Direct loss path to lending-vault bad debt whenever an Ondo RWA oracle becomes stale relative to actual NAV. The magnitude depends on (a) how stale a feed becomes during outage/weekend, (b) how much value has been lent against an Ondo-denominated collateral position, and (c) how much further the real market moves during the stale window. Losses are recoverable if the team manually forces an oracle update before the borrower exits, but that requires out-of-band monitoring that the adapter does not perform.

## Proof of Concept

No live exploit necessary — this is a structural consistency gap. The comparison table above is sufficient evidence. For any deployed `OndoOracle` instance, `_getQuote` returns the last-published NAV regardless of how long ago it was published.

## Recommendation

Introduce `maxStaleness` to the `OndoOracle` adapter, matching the existing `ChainlinkOracle`/`ChronicleOracle` pattern:

```solidity
uint256 public immutable maxStaleness;

function _getQuote(uint256 inAmount, address, address) internal view override returns (uint256) {
    (uint256 price, uint256 updatedAt) = IOndoRWAOracle(rwaOracle).getPriceWithTimestamp();
    if (block.timestamp - updatedAt > maxStaleness) revert PriceOracle_TooStale();
    return inAmount * price / 10 ** decimals;
}
```

If the underlying `IOndoRWAOracle` interface does not expose a timestamp, add a sibling contract that does, or require governance to set an off-chain monitored circuit breaker that pauses the adapter when a NAV refresh is overdue.
