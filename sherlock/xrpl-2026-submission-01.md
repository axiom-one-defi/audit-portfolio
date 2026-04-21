axiom - MPTAmount::operator+= Performs Unguarded Signed Integer Addition Leading to Undefined Behavior

## Summary

`MPTAmount::operator+=` performs bare `value_ += other.value()` on `int64_t` without any overflow guard. Signed integer overflow is undefined behavior (UB) in C++, meaning the compiler may optimize away any subsequent checks — including the invariant check in `ValidMPTPayment`. Combined with `AllowMPTOverflow::Yes` in the transfer paths, this UB is reachable when issuer payments push `OutstandingAmount` toward `INT64_MAX`.

## Root Cause

**1. Unguarded signed addition in `MPTAmount::operator+=`**

[`src/libxrpl/protocol/MPTAmount.cpp#L5-L10`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/protocol/MPTAmount.cpp#L5-L10):
```cpp
MPTAmount&
MPTAmount::operator+=(MPTAmount const& other)
{
    value_ += other.value();  // int64_t + int64_t, no overflow check
    return *this;
}
```

`value_` is declared as `value_type = std::int64_t` ([`include/xrpl/protocol/MPTAmount.h#L22`](https://github.com/XRPLF/rippled/blob/e2e537b/include/xrpl/protocol/MPTAmount.h#L22)). Per C++ standard [expr.add], signed integer overflow is UB. The compiler is free to assume it never happens and may optimize code paths that would only execute on overflow.

**2. Invariant check uses the same UB arithmetic**

[`src/libxrpl/tx/invariants/MPTInvariant.cpp#L344-L364`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/tx/invariants/MPTInvariant.cpp#L344-L364) — `ValidMPTPayment::finalize` computes `data.outstanding[Before] + data.mptAmount` using `int64_t` addition. If this overflows, the compiler may treat the entire branch as dead code and eliminate the invariant check silently.

**3. Invariant enforcement is conditional on `featureMPTokensV2`**

[`src/libxrpl/tx/invariants/MPTInvariant.cpp#L344`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/tx/invariants/MPTInvariant.cpp#L344):
```cpp
bool const enforce = view.rules().enabled(featureMPTokensV2);
```

Without `featureMPTokensV2`, `enforce = false` and the invariant returns `true` regardless of any detected overflow. The pre-V2 code path has zero protection.

**4. Direct send path allows overflow without V2**

[`src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1034-L1039`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1034-L1039) — `directSendNoFeeMPT` when sender is issuer:
```cpp
if (view.rules().enabled(featureMPTokensV2))
{
    if (isMPTOverflow(amt, outstanding, maxAmount, AllowMPTOverflow::Yes))
        return tecPATH_DRY;
}
(*sleIssuance)[sfOutstandingAmount] += amt;  // No guard without V2
```

Without MPTokensV2: no overflow check whatsoever. The outstanding amount is incremented directly via `(*sle)[sfMPTAmount] += amt` at line 1078, which uses the SLE's `UINT64` field (see [`include/xrpl/protocol/detail/sfields.macro#L142-L143`](https://github.com/XRPLF/rippled/blob/e2e537b/include/xrpl/protocol/detail/sfields.macro#L142-L143)) — producing defined unsigned wrapping at the ledger layer while the invariant running on `int64_t` is subject to UB.

**5. The escrow path correctly guards the same operation — confirming developer awareness**

[`src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L662-L668`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L662-L668) — `unlockEscrowMPT`:
```cpp
if (!canAdd(STAmount(mptIssue, current), STAmount(mptIssue, delta)))
    return tecINTERNAL;  // guard BEFORE write
(*sle)[sfMPTAmount] += delta;
```

The core transfer path at [`src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1078`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1078) uses the identical pattern without any `canAdd()` call. `canAdd` and `canSubtract` exist specifically for this purpose but are not called in `directSendNoFeeMPT`.

**6. `availableMPTAmount` sign/unsigned mismatch enables cascading inflation**

[`src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L817-L822`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L817-L822):
```cpp
auto const max = maxMPTAmount(sleIssuance);      // int64_t
auto const outstanding = sleIssuance[sfOutstandingAmount];  // uint64_t
return max - outstanding;                         // signed/unsigned mismatch
```

If `outstanding > max` (reachable via M-2a), the subtraction wraps, and `issuerFundsToSelfIssue` at [`src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L847-L857`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L847-L857) reports a massive available balance, enabling further offer creation and cascading supply inflation.

## Attack Path

**M-2a: Direct overflow via large issuer payment (no featureMPTokensV2)**

1. Create an MPT with `MaximumAmount = INT64_MAX`.
2. Issuer pays alice `INT64_MAX - 1000` — succeeds, `sfOutstandingAmount = INT64_MAX - 1000`.
3. Issuer pays alice `2000` — `directSendNoFeeMPT` skips the `isMPTOverflow` check (featureMPTokensV2 not enabled) and executes `(*sleIssuance)[sfOutstandingAmount] += amt` at [`TokenHelpers.cpp#L1039`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1039).
4. At the ledger layer this is `uint64_t` wrapping (defined behavior, wrong value). At the invariant layer `MPTAmount::operator+=` runs on `int64_t` — signed overflow is UB; the compiler may eliminate the invariant branch entirely.
5. `sfOutstandingAmount` is now corrupted; the invariant returns success because `enforce = false`.

**M-2a (with featureMPTokensV2): overflow via `AllowMPTOverflow::Yes`**

1. Same setup. With V2 enabled, `isMPTOverflow` runs but uses `uint64_max` as the limit when `AllowMPTOverflow::Yes` (see [`MPTokenHelpers.cpp#L835-L840`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L835-L840)), so amounts up to `UINT64_MAX` are permitted even when `MaximumAmount` is far lower.
2. DEX/AMM offer-fill paths use `AllowMPTOverflow::Yes`, so an issuer offer fill can push `OutstandingAmount` past `MaximumAmount`.

**M-2b: Invariant delta cancellation via Batch transactions**

1. Give alice and bob each `INT64_MAX / 2` MPT.
2. Submit a single Batch transaction: alice→bob `INT64_MAX/2 + 1000`, then bob→alice the same amount.
3. Each inner transaction is checked by the invariant independently (per-inner-tx scope, not per-batch). Individual balance additions in `operator+=` trigger signed overflow — UB.
4. If the compiler optimizes away the invariant check on the UB path, both balances appear correct after the batch, but the intermediate state is undefined.

**M-2c: `availableMPTAmount` sign-flip → cascading inflation**

1. Use M-2a or M-1 to push `sfOutstandingAmount > MaximumAmount`.
2. `availableMPTAmount` at [`MPTokenHelpers.cpp#L817-L822`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L817-L822) computes `max - outstanding` with a signed/unsigned mismatch — result wraps to a large positive value.
3. `issuerFundsToSelfIssue` reports a massive available balance.
4. Issuer can create additional offers backed by phantom supply, leading to cascading inflation across any DEX pool or AMM holding this MPT.

## Impact

- **Unpredictable ledger state:** UB in signed arithmetic means the C++ standard places no constraint on what the compiler produces; ledger state after overflow is implementation-defined at best, silently corrupted at worst.
- **Invariant bypass:** The compiler may optimize away `ValidMPTPayment::finalize`'s conservation check because the check itself uses UB arithmetic.
- **Supply corruption:** `sfOutstandingAmount` can exceed `MaximumAmount` or wrap to unexpected values, breaking all MPT accounting.
- **Cascading inflation (M-2c):** Once outstanding exceeds max, `availableMPTAmount` sign-flips and `issuerFundsToSelfIssue` exposes phantom balance, enabling unbounded new offer creation.
- **Cross-finding amplification:** M-2 enables the supply bypass in M-1 and amplifies AMM precision attacks.

## PoC

Three scenarios covering all sub-vectors are provided in:
[`src/test/app/MPT_overflow_test.cpp`](https://github.com/XRPLF/rippled/blob/e2e537b/src/test/app/MPT_overflow_test.cpp)

## Mitigation

1. **Add overflow guard in `operator+=`** ([`MPTAmount.cpp#L5-L10`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/protocol/MPTAmount.cpp#L5-L10)):
   ```cpp
   MPTAmount& MPTAmount::operator+=(MPTAmount const& other) {
       if (__builtin_add_overflow(value_, other.value(), &value_))
           Throw<std::overflow_error>("MPTAmount overflow");
       return *this;
   }
   ```

2. **Guard `directSendNoFeeMPT` unconditionally** ([`TokenHelpers.cpp#L1034-L1039`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/TokenHelpers.cpp#L1034-L1039)): move the `isMPTOverflow` check outside the `if (featureMPTokensV2)` block so it applies regardless of feature flag state.

3. **Fix `isMPTOverflow` limit** ([`MPTokenHelpers.cpp#L835-L840`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/ledger/helpers/MPTokenHelpers.cpp#L835-L840)): use `maximumAmount` (not `uint64_max`) when `AllowMPTOverflow::Yes` is set, so the DEX/AMM path cannot exceed the issuer-defined cap.

4. **Add pre-addition bounds check in invariant** ([`MPTInvariant.cpp#L356-L359`](https://github.com/XRPLF/rippled/blob/e2e537b/src/libxrpl/tx/invariants/MPTInvariant.cpp#L356-L359)): validate inputs BEFORE computing `outstanding[Before] + mptAmount` to avoid UB in the check itself.
