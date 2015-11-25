# HPKA 0.1, Draft spec

----------------------------------------------------

**This is still a draft spec and is potentially subject to change**

Written by Ahmad Benmrad

Email : [batikhsouri@gmail.com](mailto:batikhsouri@gmail.com)  
Twitter : [@BatikhSouri](https://twitter.com/BatikhSouri)  
Github : [https://github.com/BatikhSouri](https://github.com/BatikhSouri)

## Introduction

HPKA (acronym for HTTP Public Key Authentication) is an extension of the HTTP protocol that aims to authenticate users through public key authentication.

It has some features that are useful when you want to run a distributed, federated network.

It would allow ad-hoc user authentication, registration, deletion and key rotation

## Technical overview

There two modes of operation, "Session-less HPKA" and "HPKA with sessions". Note that latter is built upon the former.

### Session-less (standard) HPKA

On each HTTP request, the client appends some headers. This can be done regardless of what HTTP verb is used :

* `HPKA-Req`: all the details about the action type, username, public key, as described by the protocol below.
* `HPKA-Signature`: the signature of the HPKA-Req field content with the host/path of the request concatenated to it (as part of the signed content)

We should note that this solution as it is now is not safe from MITM attacks when not used over HTTPS (or a Tor hidden service). The HPKA-Req contains a timestamp, and as of now the [node-hpka](https://github.com/Mowje/node-hpka) implementations rejects payload older than 120 seconds. Hence, in case the connection to the server is not encrypted and/or not authenticated, it is possible that an attacker steals an HPKA and uses it within these 2 minutes... This flaw MAY be dodged by doing some thorough logging server-side for requests younger than 2 minutes.

If the headers mentioned above are not present in the HTTP request, then add a `HPKA-Available: 1` header when responding to the client.

If some error occurred or some mistake was made in the request, the response will have it's status code == 445. In addition to that, it will also carry an additional `HPKA-Error` header; it's value will be just an error number according to the HPKA-Error protocol described below

The signature algorithms that could be used (as of now) in HPKA are :

* [RSA](http://en.wikipedia.org/wiki/RSA_cryptosystem)
* [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
* [ECDSA](http://en.wikipedia.org/wiki/ECDSA)
* [Ed25519 (SUPERCOP implementation, as used in libsodium)](https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html)

### HPKA with session

Even though HPKA was designed with a target usage within distributed networks of servers, users might still connect multiple times to the same server. In that case, it might seem redundant (and sometimes bad for performance) for sign every request.

Instead, the client go through a special authentication process, less frequently and in a near-periodic manner, at the end of which a user-generated SessionId becomes known to the server in question.

The client could attach a wished expiration date for that SessionId. The server in its response indicates to the client the effective expiration date in a `HPKA-Session-Expiration` header (as UTC Unix Epoch, in seconds). This "session expiration date agreement" is intended to let a server make a session expire before the client wants to, in case the validity period is too long.

The client then uses the agreed-upon SessionId in his subsequent authenticated HTTP requests by adding an `HPKA-Session` header (as described below in the HPKA-Session protocol), instead of using HPKA with ActionType == 0x00.

__NOTE:__ When HPKA sessions are used within a distributed network, the client should not share a given SessionId with more than one server.

__Why not use cookies instead? It has everything you need when using SessionIds.__

No, it doesn't. Although cookies are potentially easier to use, they lack something very important : the ability to be stored safely. Usage of cookies implies that they will most likely be saved in the browser, unencrypted. But since HPKA SessionIds are supposed to replace the usage of a cryptographic keypair (that should be protected by a passphrase, as said below), we must ensure that they are stored securely.

## Security overview

A similar system (public key authentication of clients) has been implemented through TLS/SSL client certificates. However, the authentication there is done on TLS/SSL level and not HTTP. Furthermore, client certificates are delivered by the server/service and are signed by a CA on delivery. That last point means that it's not possible to use a client certificate to authenticate on an other server that wouldn't recognize the CA used by the server on which the account as created (after an account transfer, for example); hence there would be a CA-dependency, which is potentially something you want to get rid of when you want to run a distributed network of servers.

The difference here with HPKA is that the users generates his own key pair and signs his public key with his private key on registration. Then he appends specific HTTP headers on each request, each time with a new signature (in case of standard, session-less HPKA).

Furthermore, this technique brings some advantages over usual username/password authentication methods. For example, if a badly-built website using that traditional method is "hacked", the hackers can't hack all users at once by dumping a passwords or hashes DB. An other example is that, given a "flawless" web application that uses HPKA, it is probably much harder to hack a specific user account because you would have to compromise the user's device first on order to get the user's private key.

For improved security, the user's key file should be protected by a passphrase, so in case the user's device is compromised in any way, the account would be compromised if and only if the attacker was able to decrypt the key file through a (hopefully) expensive password attack (assuming the user wouldn't give him the password...)

**Note about the use of the ECDSA:**  
This protocol supports ECDSA signatures. Note that this algorithm uses the NIST-designed, NSA-approved elliptic curves. We are aware of the Dual-EC-DRBG backdoor implanted by the NSA. And specialists are supposing that these elliptic curves used in ECDSA are also potentially backdoored, because they use magic constants without clear rationale (unlike the curve used in Curve25519/Ed25519 that have been openly specified by researchers from the academic world, and not by government contractors; motives please). So please keep that in mind when using HPKA with ECDSA signatures.

**Side note about TLS and CAs:**  
Further on, I'll say in the small threat model below that a service using HPKA should be hosted somehow securely (HSTS or Tor hidden service). I know there is a contradiction between HSTS and the fact we maybe shouldn't trust CAs as much as we do. But, we can actually do without them in our case : a user will call the same server many times, so certificate pinning of a self-signed certificate should be enough. Otherwise, for first time users there isn't a way as much accepted/used as TLS/SSL for authenticating a server.

## Threat model

We describe here our assumptions about the user's computer, and what an attacker can achieve (probably incomplete) :

* The user acts reasonably. He would not give the password of his key file to an attacker for example
* The user's computer
	* Uses a properly implemented HPKA client
	* Is not infected by malware
* The service uses [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) or a [Tor hidden service](https://www.torproject.org/docs/hidden-services). Alternatively, an attacker must not be able to eavesdrop on a connection between the server and the client, in addition of them having the ability to check the integrity of the requests and responses. Ideally, the client checks the identity of the server by checking his public key or the fingerprint of his certificate using a safe hashing function (i.e. : certificate pinning).
* The server must check that timestamps of requests are "incremental" (for both Standard HPKA and Session-based HPKA)
* All services on a given hostname are controlled by the same party
* We assume that the "unforgeability" & "integrity" properties provided by [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm), [RSA](https://en.wikipedia.org/wiki/RSA_cryptosystem), [ECDSA](https://en.wikipedia.org/wiki/ECDSA) and [Ed25519](http://ed25519.cr.yp.to/) signature schemes is valid. Also we assume that the "random constants" used the [most common curves](http://www.secg.org/collateral/sec2_final.pdf) are safe in case we choose to use ECDSA.

## Protocols

### HPKA-Req protocol

__NOTES :__

* Everything is written in Big Endian
* No encoding is used for key's elements
* Lengths are expressed in bytes
* For Ed22519, the chosen implementation (the SUPERCOP implementation) implies that by default the produced [signatures have the signed message concatenated to it](http://blog.mozilla.org/warner/files/2011/11/key-formats.png). In our case, this is useless data overhead, since the signed message can be "reconstructed" from the HPKA-Req header, the path and host values used in the HTTP request. Hence in HPKA we use detached Ed25519 signatures (which are signatures without the signed message prepended to it)

__The Req payload is constructed as follows (in that order) :__

* Version number : one byte. Only value for now: 0x01
* UTC Unix Epoch (timestamp since 1-1-1970 00:00:00 UTC, in seconds) (8 bytes long)
* Username.length (one byte)
* Username (Username.lenght bytes long)
* ActionType (one byte)
* Key type : one byte. Values possible are:
	* 0x01 for ECDSA
	* 0x02 for RSA
	* 0x04 for DSA
	* 0x08 for Ed25519
* Then, depending on the key type
	* If keyType == ECDSA (== 0x01)
		* publicPoint.x.length (unsigned 16-bit integer)
		* publicPoint.x
		* publicPoint.y.length (unsigned 16-bit integer)
		* publicPoint.y
		* curveID (one byte)
	* If keyType == RSA (== 0x02)
		* modulus.length (unsigned 16-bit integer)
		* modulus
		* publicExponent.length (unsigned 16-bit integer)
		* publicExponent
	* If keyType == DSA (== 0x04)
		* primeField.length (unsigned 16-bit integer)
		* primeField
		* divider.length (unsigned 16-bit integer)
		* divider
		* base.length (unsigned 16-bit integer)
		* base
		* publicElement.length (unsigned 16-bit integer)
		* publicElement
	* If keyType == Ed25519 (== 0x08)
		* publicKey.length (unsigned 16-bit integer) (note that it will usually be always the same size, i.e 32 bytes)
		* publicKey
* If ActionType == SessionIdCreation (== 0x04) Or ActionType == SessionIdDeletion (== 0x05)
	* SessionId.length (one byte)
	* SessionId (SessionId.length bytes long)
* If ActionType == SessionIdCreation (== 0x04)
	* WantedExpirationDate (As UTC Unix Epoch) (8 bytes long)

At this stage, the Req payload is [base64](en.wikipedia.org/wiki/Base64) encoded and then set as the value of the "HPKA-Req" header. That same Req payload (before encoding) has the "verbID|hostname/fullpath" string appended to it before being signed (a detached signature, as described earlier); the signature is then base64 encoded as well, before being set as "HPKA-Signature" header value. For signature schemes other than Ed25519, the hash function used is [SHA1](http://en.wikipedia.org/wiki/SHA-1). (Notes for the "verbId|hostname/fullpath" : "|" is the concatenation operation, examples: "0x01|google.com/index.htm" "0x01|service.tld/search?q=test&lang=en"; port numbers are omitted, even if different than 80 or 443; /fullpath is the path followed by the query string if there is one)

__ActionType :__  
Here are the possible values for the ActionType field, depending on the type of the actual request.

Value | Meaning
------|--------
0x00  | Normal (authenticated) HTTP request
0x01  | Registration
0x02  | Account deletion
0x03  | Key rotation
0x04  | Session ID creation
0x05  | Session ID deletion

__VerbID :__  
Here are the values for the different HTTP verbs possible

Value | HTTP Verb
------|----------
 0x01 | GET
 0x02 | POST
 0x03 | PUT
 0x04 | DELETE
 0x05 | HEAD
 0x06 | TRACE
 0x07 | OPTIONS
 0x08 | CONNECT
 0x09 | PATCH

__CurveID :__  
Here are the possible values for the curveID field, and to what curve they correspond

 CurveID | Curve name
-------- | -----------
 0x01    | secp112r1
 0x02    | secp112r2
 0x03    | secp128r1
 0x04    | secp128r2
 0x05    | secp160r1
 0x06    | secp160r2
 0x07    | secp160k1
 0x08    | secp192r1
 0x09    | secp192k1
 0x0A    | secp224r1
 0x0B    | secp224k1
 0x0C    | secp256r1
 0x0D    | secp256k1
 0x0E    | secp384r1
 0x0F    | secp521r1
 0x80    | sect113r1
 0x81    | sect113r2
 0x82    | sect131r1
 0x83    | sect131r2
 0x84    | sect163r1
 0x85    | sect163r2
 0x86    | sect163k1
 0x87    | sect193r1
 0x88    | sect193r2
 0x89    | sect233r1
 0x8A    | sect233k1
 0x8B    | sect239r1
 0x8C    | sect283r1
 0x8D    | sect283k1
 0x8E    | sect409r1
 0x8F    | sect409k1
 0x90    | sect571r1
 0x91    | sect571k1

### HPKA-Error protocol

Here is the different error numbers for the HPKA-Error header, in case some error occurred

Value | Meaning
------|---------
  1   | Malformed request
  2   | Invalid signature or invalid token
  3   | Invalid key *
  4   | Unregistered user *
  5   | Username not available (on registration) *
  6   | Forbidden action *
  7   | Unsupported action type *
  8   | Unknown action type *
  9   | Invalid new key (when rotating keys) *
  10  | Invalid signature for the new key (when rotating keys)
  11  | Username field can't be left blank *
  12  | Forbidden key type *
  13  | Invalid route *
  14  | Signature expired
  15  | Refused sessionId registration

Note : Error codes marked with a "\*" means that these errors have to be managed on the application level.

### HPKA-Session protocol

When a server supports sessions receives an authenticated request of a registered user (i.e. ActionType == 0x00), it can include a `HPKA-Session: 1` header in its response to let the client know of the availability of that feature.

To agree upon a SessionId, the client sends a special HPKA-Req with ActionType == 0x04, that contains the SessionId to be agreed-upon. Optionally, it can contain a wished expiration date for that SessionId. (As described in the HPKA-Req protocol)

If the request is valid, the server responds with a `HPKA-Session-Expiration` header, whose value is the accepted expiration date for the SessionId. If the client provided a wished expiration date, this returned value can only be inferior or equal to the value provided by the client (allowing the server to enforce shorter SessionId lifespans). If the client didn't send a wished expiration date and the server doesn't need to enforce one, the `HPKA-Session-Expiration` can be equal to 0, meaning that SessionId can be used until the client revokes it.

While the SessionId is still valid, subsequent requests by the client will have a `HPKA-Session` header that will replace the `HPKA-Req` and `HPKA-Signature` headers.

__The `HPKA-Session` header built as follows (in that order):__

* Version number : one byte. Only for now : 0x01
* Username.length (one byte)
* Username (Username.length bytes long)
* Timestamp (8 bytes, UTC Unix Epoch, in seconds)
* SessionId.length (one byte)
* SessionId (SessionId.length bytes long)

This payload is then encoded to Base64.

A SessionId can be revoked by the client by sending a HPKA-Req with ActionType == 0x05 and the corresponding SessionId. When a server supports SessionIds, it __must__ also support their revocation by the user.

The server can be set-up to disallow HPKA-Session. In that case, it returns `HPKA-Error: 7` when receiving HPKA-Req with ActionType == 0x04 or ActionType == 0x05, or when receiving `HPKA-Session` headers.

If the server choose not to accept a sessionId (for example, too much sessions registered for a given user), it returns a `HPKA-Error: 15` header.

### HPKA User registration

When a user wants to register on the website using his public key, he appends the HPKA-Req (with ActionType == 0x01) and HPKA-Signature fields on a GET request on the website's home page. If the username is available, the server registers it and responds to the user with a "normal" response (status code = 200). Otherwise it will return status code 445, with a HPKA-Error: 5

If a user wants the server to generate a username for him, the username field from HPKA-Req should be left blank.

### HPKA User deletion

The user sends a signed HPKA-Req header with the corresponding actionType value. The HTTP response is a "normal" one (i.e., status code = 200) if it succeeds.

### HPKA Key rotation

The user sends a signed HPKA-Req header with the corresponding actionType value. In addition to that, he sends an other HPKA-Req payload with the containing the new key and with the same actionType value in a "HPKA-NewKey" field. This field is signed by both the actual key and the new key, and the signatures are respectively sent on "HPKA-NewKeySignature" and "HPKA-NewKeySignature2" fields. The HTTP response is a "normal" one (i.e., status code = 200) if it succeeds.

## Libraries

As of now, I have written two libraries for HPKA 0.1 :

* [node-hpka](https://github.com/Mowje/node-hpka) : server-side authentication library for Node.js, acts as an expressjs middleware
* [hpka.js](https://github.com/LockateMe/hpka.js) : In browser implementation of HPKA, built to be used with [libsodium.js](https://github.com/jedisct1/libsodium.js). Supports Ed25519 only
