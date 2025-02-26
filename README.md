# dart_ssi
Dart Package supporting several standards in SSI space, inclusive a minimal wallet implementation based on [Hive](https://docs.hivedb.dev/#/). 
This Package contains classes and functions for storing verifiable credentials
and relating key-pairs; issue, verify and revoke credentials and presentations.
Additional two exchange protocols ([OID4VC](https://openid.net/sg/openid4vc/) and 
[DIDComm V2](https://identity.foundation/didcomm-messaging/spec/)) for Credentials and Presentations are supported.

**Important Note**: This package is work-in-progress. The API is subject to change.

## Wallet

To setup a Wallet just do this:
```
var wallet = new WalletStore('holder');
await wallet.openBoxes('holderPW');
```

The wallet implementation offers a flexible chose of the keystorage. Per default a software keystore
based on Hive is used. To change this or to add an additional one implement it by extending the abstract class 
_KeyStoreBackend_. This class and the default software implementation can be found [here](./lib/src/wallet/key_storage.dart)

## Credentials
This packages supports the [Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model-1.1/) and 
Linked Data Proofs. For now [JsonWebSignature2020](https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/) and [Ed25519Signature2020](https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/) are supported.

An example how to sign and verify a Credential and a Presentation can be found [here](./example/credential.dart)

### Some Notes on Linked Data Proofs
- for security and performance reasons some important Json-ld contexts are bundled with this library. These are:
  - https://schema.org
  - https://www.w3.org/2018/credentials/v1
  - https://w3id.org/security/suites/secp256k1recovery-2020/v2
  - https://w3id.org/security/suites/ed25519-2020/v1
  - https://identity.foundation/presentation-exchange/submission/v1/
- The function used to load context is implemented that way that it only loads the named contexts. It will not download things from the web. All functions that need such a document loader have an optional parameter `loadDocumentFunction`. This means you can write your own function for loading contexts if needed.
- The [safeMode option](https://pub.dev/packages/json_ld_processor#safemode-option) of the Json-ld processor is set to true

## Decentralized Identifiers (DID)
To resolve a Did-Document belonging to a DID use 
```
var document = resolveDidDocument(did);
```
The resolution of did:key and did:web is built in, for every other did an url to a resolver instance must be given.
Per default the keys in the did-document are given in multibase-format and, if a key is used multiple times, included 
based on its id. To resolve the ids and convert all keys in JWK-Format use
```
document = document.resolveKeyIds();
document = document.convertAllKeysToJwk();
```

## OID4VC

## Didcomm
This package supports the [Didcomm V2 message format](https://identity.foundation/didcomm-messaging/spec/). Except of the optional XChaCha20Poly1305 Encryption all Encryption, Key Agreement, Key Wrap and signing
Algorithms mentioned in the spec are supported.
From a message level perspective the following Message/Protocols are supported:
- [Empty Message](https://identity.foundation/didcomm-messaging/spec/#the-empty-message)
- [Problem Report](https://identity.foundation/didcomm-messaging/spec/#problem-reports)
- [Discover Feature 2.0](https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20)
- [Out-Of-Band Message](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages)
- [issue-credential V3](https://github.com/decentralized-identity/waci-presentation-exchange/tree/main/issue_credential) with [JSON-LD Credential Attachment](https://github.com/hyperledger/aries-rfcs/tree/main/features/0593-json-ld-cred-attach)
- [present-proof V3](https://github.com/decentralized-identity/waci-presentation-exchange/blob/main/present_proof/present-proof-v3.md) with [DIF Presentation Exchange Attachment](https://github.com/hyperledger/aries-rfcs/tree/main/features/0510-dif-pres-exch-attach) and the slightly change that this packages uses [V2 of presentation exchanges](https://identity.foundation/presentation-exchange/) and tries to support all features of it and not only the listed ones in the definition of the attachment format.


A full example for issuing a credential and requesting a presentation using didcomm can be found in [didcomm.dart](./example/didcomm.dart) 

### Differences to Didcomm spec
- This library supports explizit two additional headers for the plaintext messages not mentioned in the spec. These are `reply_url` and `reply_to`. 
  Both are described in [JWM-Spec](https://datatracker.ietf.org/doc/html/draft-looker-jwm-01), the didcomm plaintext messages are based on. 
  They are useful, when didcomm is used with a did-method that do not support service endpoints or to clarify which service endpoint from a did-document should be used.

## More Examples
With [Hidy](https://github.com/b2cm/id_ideal_wallet) you have a fully featured mobile wallet based on this library.
    


