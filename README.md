# WebAuthn PoC

1. The Authenticator actually signs not the challenge, but rather a pair of client data and authenticator data, where the former ALSO contains the challenge in it.
That means that if the challenge is the hash of a payload, in order to verify the signature it will not be enough to have just the payload: also all those other info are needed.
So anybody who wants to verify this signature, would need to know also this data (ref: item 11 on https://www.w3.org/TR/webauthn-2/#authenticatorgetassertion).

2. The algorithm used for signing changes over time, and that's up to 1) The RP allowed list 2) The authenticator implemented ones. Thus, Assertion verification logic changes over time.  
Browser, OS and libraries keep up to date with these changes, and the contract should do the same to be time-proof, implementing the new algorithms as they come up. For instance, in the library I implemented they are already changing them to keep up with the new standards 
coming up (ref: <https://github.com/MasterKale/SimpleWebAuthn/issues/260>).

3. There's a missing piece here: we have 2 flows.
- Attestation (used for registration) where signatures are generated not with the newly created credential private key, but with the authenticator's attestation private key.  
- Assertion (user for authentication) where signatures are generated with the newly created credential private key.

About the attestation, are those public key used by authenticators always trusted? Ref:
- <https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-private-key>
- <https://medium.com/webauthnworks/webauthn-fido2-demystifying-attestation-and-mds-efc3b3cb3651>

Some are already deprecated, like Apple Anonymous Attestation (see here <https://medium.com/webauthnworks/verifying-fido2-responses-4691288c8770> and <https://medium.com/webauthnworks/webauthn-fido2-verifying-apple-anonymous-attestation-5eaff334c849>).

4. Non-resident key functioning still obscure to me: <https://crypto.stackexchange.com/questions/105942/how-do-non-resident-keys-work-in-webauthn>

Final note: The amount of machinery involved to work (eg: decode, transmit) the underlying data is astonishing.
