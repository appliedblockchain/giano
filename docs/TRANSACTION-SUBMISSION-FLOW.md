# Transaction submission flow — "Transfer 69 USDC"

This diagram traces a single ERC-20 transfer through the Giano two-origin, ERC-4337
stack: from the button click in the sample dApp (`services/custom-example`) to the
moment the signed UserOperation is accepted by the bundler, and on to the receipt.

Key properties visible in the flow:

- **Origin isolation.** The dApp bundle ships no WebAuthn, credential, bundler or
  paymaster code. Everything trust-related runs on the **wallet origin** popup and is
  reached only over zod-validated JSON-RPC-over-`postMessage`.
- **Tx → UserOp.** `eth_sendTransaction` is repackaged into an EntryPoint v0.7
  UserOperation inside the wallet (`wallet-core` provider), gas-estimated and prepared
  against the bundler/paymaster, signed by the passkey, then relayed.
- **Policied relay.** The signed op is not sent straight to the bundler by the browser;
  it goes through **wallet-api**, which recomputes the hash against its *own* EntryPoint,
  runs policy, logs, and only then forwards to the bundler.
- **Sponsorship.** The paymaster (here the permissive testing paymaster, keyed by
  `config.paymasterAddress`) is attached during gas estimation / preparation so the op
  is gas-sponsored.

Code anchors: `Erc20Panel.tsx` · `create-giano-wallet-provider.ts` (thin SDK) ·
`wallet-transport` client/host · `wallet-web/src/host.ts` + `wallet.ts` ·
`wallet-core/src/provider.ts` · `account/toGianoSmartAccount.ts` ·
`create-wallet-api-injection.ts` · `wallet-api/src/routes/userops.ts` + `services/bundler.ts`.

```mermaid
sequenceDiagram
    autonumber
    actor User

    box rgba(120,160,255,0.12) dApp origin (app.example.com)
        participant UI as dApp UI<br/>(Erc20Panel)
        participant Thin as Thin provider<br/>(giano-connector)
        participant Read as publicClient<br/>(read RPC)
    end

    participant TP as postMessage<br/>transport

    box rgba(120,255,160,0.12) Wallet origin popup (wallet.example.com)
        participant Host as Wallet host<br/>+ Review view
        participant GP as Giano provider<br/>(wallet-core)
        participant Acct as Smart account<br/>(toGianoSmartAccount)
        participant BC as Bundler client<br/>(viem + paymaster cfg)
    end

    actor PK as Passkey authenticator<br/>(device / WebAuthn)
    participant API as wallet-api<br/>(policy + relay)
    participant Bundler as ERC-4337 bundler<br/>(Alto)
    participant PM as Paymaster<br/>(contract)
    participant Node as Blockchain node<br/>(RPC + EntryPoint)

    %% ---------- 1. Click & encode (dApp side) ----------
    User->>UI: Click "Transfer 69 USDC"
    activate UI
    Note over UI: encodeFunctionData(erc20.transfer,<br/>[to, 69_000000])  // 6 decimals
    UI->>Thin: request eth_sendTransaction<br/>[{ to: USDC, data }]
    activate Thin

    %% ---------- 2. Cross-origin transport ----------
    Note over Thin: eth_sendTransaction ∈ WALLET_METHODS<br/>→ must go to the popup
    Thin->>TP: open popup + handshake<br/>(if not already connected)
    TP->>Host: rpc "eth_sendTransaction"<br/>(zod-validated envelope)
    activate Host

    %% ---------- 3. Consent (wallet origin) ----------
    opt in-memory account lost (popup reopened)
        Host->>GP: giano_restoreAccount
        GP->>API: GET public-key by credentialId (Bearer session)
        API-->>GP: { x, y }
        Note over GP,Acct: rebuild smart account from stored<br/>pubkey — NO passkey prompt here
    end
    Host->>User: Show ReviewTransaction<br/>(to, token, amount, origin)
    User-->>Host: Approve
    Host->>GP: request eth_sendTransaction

    %% ---------- 4. Build the UserOperation ----------
    activate GP
    Note over GP: calls = [{ to: USDC, value: 0, data }]<br/>submitUserOperation({ calls, account })
    GP->>BC: estimateUserOperationGas(userOp)
    activate BC
    BC->>BC: getPaymasterStubData()<br/>→ { paymaster }
    BC->>Node: eth_estimateUserOperationGas<br/>(via bundler RPC)
    Node-->>BC: gas limits (verificationGasLimit ≥ 800k for WebAuthn)
    BC-->>GP: gas estimate
    GP->>BC: prepareUserOperation({...op, ...estimate})
    BC->>Node: get nonce (EntryPoint.getNonce), account code
    Note over BC,Acct: encodeCalls → execute(to,0,data)<br/>getFactoryArgs → factory/factoryData<br/>(only if account not yet deployed)
    BC->>BC: getPaymasterData() → { paymaster }
    BC-->>GP: prepared UserOperation
    deactivate BC
    GP->>Read: estimateFeesPerGas()
    Read->>Node: eth_feeHistory / gasPrice
    Node-->>Read: maxFeePerGas / maxPriorityFeePerGas
    Read-->>GP: fees
    Note over GP: resolveUserOpFees:<br/>requested → prepared → chain estimate

    %% ---------- 5. Sign with the passkey ----------
    GP->>Acct: signUserOperation(preparedWithGas)
    activate Acct
    Note over Acct: hash = getUserOperationHash(chainId,<br/>EntryPoint v0.7, userOp)<br/>wrapped in replay-safe EIP-712
    Acct->>PK: navigator.credentials.get(challenge = hash)
    PK->>User: Biometric / PIN prompt
    User-->>PK: Authenticate
    PK-->>Acct: WebAuthn assertion (r, s, authenticatorData, clientDataJSON)
    Note over Acct: toWebAuthnSignature + wrapSignature<br/>→ SignatureWrapper(ownerBytes, sig)
    Acct-->>GP: signature
    deactivate Acct

    %% ---------- 6. Policied relay to the bundler ----------
    Note over GP: signedUserOp = prepared + sender + signature
    GP->>API: POST /v1/userops<br/>{ userOperation } (Bearer session)
    activate API
    Note over API: recompute hash vs SERVER EntryPoint/chain<br/>evaluatePolicy(gas caps, target, paymaster)<br/>insert userop_log (status: accepted)
    alt policy rejects
        API-->>GP: 403 policy-rejected (+ rule results)
        GP-->>Host: error
        Host-->>UI: rejected
    else policy allows
        API->>Bundler: eth_sendUserOperation(rpcOp, entryPoint)
        activate Bundler
        Bundler->>Node: simulateValidation (EntryPoint)
        Node->>PM: validatePaymasterUserOp (sponsor check)
        PM-->>Node: sponsorship OK / prefund
        Node-->>Bundler: validation OK
        Bundler-->>API: userOpHash
        deactivate Bundler
        Note over API: userop_log → status: submitted
        API-->>GP: { userOperationHash }
    end
    deactivate API
    GP-->>Host: userOpHash
    deactivate GP
    Host-->>TP: rpc:response userOpHash
    deactivate Host
    TP-->>Thin: userOpHash
    Thin-->>UI: userOpHash  ← signed UserOp submitted to bundler ✅
    deactivate Thin
    Note over UI: notifyInfo("Transfer submitted — waiting for receipt…")

    %% ---------- 7. Await inclusion (receipt) ----------
    UI->>Thin: request waitForUserOperationReceipt [hash]
    activate Thin
    loop poll every 2s, up to 120s
        Thin->>API: GET /v1/userops/:hash/receipt (public)
        API->>Bundler: eth_getUserOperationReceipt(hash)
        Bundler-->>API: receipt or null
        API-->>Thin: { receipt }
    end
    Note over Bundler,Node: meanwhile the bundler batches the op into<br/>EntryPoint.handleOps → mined on-chain
    Thin-->>UI: receipt { success }
    deactivate Thin
    UI->>User: notifySuccess("Transfer confirmed") / error if reverted
    deactivate UI
```

## Notes on the two submission paths

`wallet-core`'s `submitUserOperation` has **two** branches (`provider.ts`):

- **With the wallet-api injection hook (shown above, the default for `wallet-web`)** —
  the provider estimates + prepares + signs locally, then hands the *signed* op to
  `injection.submitUserOperation`, which `POST`s to `wallet-api`. The bundler is only
  ever reached by the backend, after policy. The dApp never holds a bundler URL.
- **Without the hook** — the provider calls `bundler.sendUserOperation(userOpRequest)`
  directly (viem's account-abstraction client builds, signs and submits in one call).
  This is the embedded/no-backend path.

The paymaster is attached purely by the bundler client's `getPaymasterStubData` /
`getPaymasterData` (configured in `wallet.ts` from `config.paymasterAddress`). The
on-chain sponsorship decision (`validatePaymasterUserOp`) happens at bundler
validation / EntryPoint execution time, not in the browser.
