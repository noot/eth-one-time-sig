# Ethereum one-time signatures

This library utilizes `ecrecover` to generate a valid signature over some message without any provided private key. Essentially, some random values are used as the signature, and when this is passed to `ecrecover`, it returns some public key (and thus account address).

This could also be called "one-time accounts" or "one-time transactions" (if used to sign a transaction).

This allows for one, and only one, transaction to be sent from some newly-created account. If this account is funded by some party (or parties), this could be used for multisigs or group contract deployments, for example.

#### Example 
Say someone wants to deploy a contract, but it's really expensive, and they want their community/DAO/friends/family to help pay to deploy it.

1. Some publicly known seed is determined, which is used to help generate the "signature". Everyone must be able to verify the signature was derived from the seed. This prevents someone from creating a signature/message pair where they actually do know the private key.
2. The message, in this case, a "deploy contract" transaction, is created. A one-time signature is also created on it using the seed.
3. The signature creator publishes the one-time signature and its corresponding public key; all others verify it.
4. If verified, other users then send their funds to the address corresponding to the public key.
5. Once the account has enough funds, anyone can submit the transaction to deploy the contract.

