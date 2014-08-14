# HPKA 0.1, Draft spec

----------------------------------------------------

**This is still a draft spec and is potentially subject to change**

Written by Ahmad Ben Mrad

Email : [batikhsouri@gmail.com](mailto:batikhsouri@gmail.com)  
Twitter : [@BatikhSouri](https://twitter.com/BatikhSouri)  
Github : [https://github.com/BatikhSouri](https://github.com/BatikhSouri)

## Introduction

HPKA (acronym for HTTP Public Key Authentication) is an extension of the HTTP protocol that aims to authenticate users through public key authentication.

It has some features that are useful when you want to run a distributed, federated network.

It would allow adhoc user authentication, registration, deletion and key rotation

## Technical overview

On each HTTP request, the client appends some headers. This can happen regardless of what HTTP verb is used :

* HPKA-Req: all the details about the action type, username, public key, as described by the protocol below.
* HPKA-Signature: the signature of the HPKA-Req field content with the host/path of the request concatenated to it (as part of the signed content)

We should note that this solution as it is now is not safe from MITM attacks when not used over HTTPS (or a Tor hidden service). The HPKA-Req contains a timestamp, and as of now the [node-hpka](https://github.com/Tashweesh/node-hpka) implementations rejects payload older than 120 seconds. Hence, in case the connection to the server is not encrypted and/or not authenticated, it is possible that an attacker steals an HPKA and uses it within these 2 minutes... This flaw could be dodged by doing some thourough logging server-side for requests youngest than 2 minutes.

If the headers mentioned above are not present in the HTTP request, then add a "HPKA-Available: 1" header when responding to the client.

If some error occured or some mistake was made in the request, the reponse will have it's status code == 445. In addition to that, it will also carry an additional "HPKA-Error" header; it's value will be just an error number according to the HPKA-Error protocol described below

The signature algorithms that could be used (as of now) in HPKA are :

* [RSA](http://en.wikipedia.org/wiki/RSA_cryptosystem)
* [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
* [ECDSA](http://en.wikipedia.org/wiki/ECDSA)
* [Ed25519 (SUPERCOP implementation, as used in libsodium)](http://doc.libsodium.org/public-key_cryptography/public-key_signatures.html)

## Security overview

A similar system (client public key authentication) has been implemented through TLS/SSL client certificates. However, the authentication there is done on TLS/SSL level and not HTTP. Furthermore, client certificates are delivered by the server/service and are signed by a CA on delivery. That last point means that it's not possible to use a client certificate to authenticate on an other server that wouldn't recognize the CA used by the server on which the account as created (after an account transfer, for example); hence there would be a CA-dependency, which is potentially something you want to get rid off when you want to run a distributed network of servers.

The difference here with HPKA is that the users generates his own key pair and signs his public key with his private key on registration. Then he appends specific HTTP headers on each request, each time with a new signature.

Furthermore, this technique brings some advantages over usual username/password authentication methods. For example, if a badly-built website using that traditional method is "hacked", the hackers can't hack all users at once by dumping a passwords or hashes DB. An other example is that, given a "flawless" web application that uses HPKA, it is probably much harder to hack a specific user account because you would have to compromise the user's device first on order to get the user's private key.

For improved security, the user's key file should use a passphrase, so in case the user's device is compromised in any way, the account would be compromised if and only if the attacker was able to decrypt the key file through an expensive password attack (assuming the user wouldn't give him the password...)

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
* The service uses [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) or a [Tor hidden service](https://www.torproject.org/docs/hidden-services). Equivalently, we must not be able to eavesdrop on a connection between the server and the client, in addition to check the integrity of the requests and responses
* The server must check that timestamps of requests are "incremental"
* We assume that the security level provided [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm), [RSA](https://en.wikipedia.org/wiki/RSA_cryptosystem) and [ECDSA](https://en.wikipedia.org/wiki/ECDSA) signature schemes is valid. Also we assume that the [most common curves](http://www.secg.org/collateral/sec2_final.pdf) are safe in case we choose to use ECDSA. Same thing for Ed25519.

## Protocols

### HPKA-Req protocol

__NOTES :__

* Everything is written in Big Endian
* No encoding is used for key's elements
* Lengths are expressed in bytes
* For Ed22519, the chosen implementation (the SUPERCOP implementation) implies that by default the produced [signatures have the signed message concatenated to it](http://blog.mozilla.org/warner/files/2011/11/key-formats.png). In our case, this is useless data overhead, since the signed message can be "reconstructed" from the HPKA-Req header, the path and host values used in the HTTP request. Hence in HPKA we use deteched Ed25519 signatures (which are signatures without the signed message appended to it)

__The Req payload is constructed as follows (in that order) :__

* Version number : one byte. Only value for now: 0x01
* UTC Unix Epoch (timestamp since 1-1-1970 00:00:00 UTC, in seconds) (8 bytes long)
* Username.length (one byte)
* Username
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
		* publicKey.length (unsigned 16-bit integer) (note that it will usually be always the same size, ie 32 bytes)
		* publicKey

At this stage, the Req payload is [base64](en.wikipedia.org/wiki/Base64) encoded and then set as the value of the "HPKA-Req" header. That same Req payload (before encoding) has the "hostname/path" string appended (example: "google.com/index.htm"; port numbers are omitted, even if different than 80) to it before being signed (a detached signature, as described earlier); the signature is then base64 encoded as well, before being set as "HPKA-Signature" header value. For signature schemes other than Ed25519, the hash function used is [SHA1](http://en.wikipedia.org/wiki/SHA-1).

__ActionType :__  
Here are the possible values for the ActionType field, depending on the type of the actual request.

Value | Meaning
------|--------
0x00  | Normal (authenticated) HTTP request
0x01  | Registration
0x02  | Key rotation
0x03  | Account deletion

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

Here is the different error numbers for the HPKA-Error header, in case some error occured

Value | Meaning
------|---------
  1   | Malformed request
  2   | Invalid signature
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

Note : Error codes marked with a "*" means that these errors have to be managed on the application level.  

### HPKA User registration

When a user wants to register on the website using his public key, he appends the HPKA-Req (with ActionType == 0x01) and HPKA-Signature fields on a GET request on the website's home page. If the username is available, the server registers it and responds to the user with a "normal" reponse (status code = 200). Otherwise it will return status code 445, with a HPKA-Error: 5

If a user wants the server to generate a username for him, the username field from HPKA-Req should be left blank.

### HPKA User deletion

The user sends a signed HPKA-Req header with the corresponding actionType value. The HTTP response is a "normal" one (ie, status code = 200) if it succeeds.

### HPKA Key rotation

The user sends a signed HPKA-Req header with the corresponding actionType value. In addition to that, he sends an other HPKA-Req payload with the containing the new key and with the same actionType value in a "HPKA-NewKey" field. This field is signed by both the acutal key and the new key, and the signatures are respectively sent on "HPKA-NewKeySignature" and "HPKA-NewKeySignature2" fields. The HTTP response is a "normal" one (ie, status code = 200) if it succeeds.

## Libraries

As of now, I have written two libraries for HPKA 0.1 :

* [node-hpka](https://github.com/Tashweesh/node-hpka) : server-side authentication library for Node.js, acts as an expressjs middleware
* [cpp-hpka](https://github.com/Tashweesh/ccp-hpka) : some C++ classes with static methods, letting you build [HPKA client payloads](#hpka-req-protocol). Depends on [Crypto++](http://cryptopp.com) (Doesn't manage the network connections though)

## Example apps

I have written examples that use HPKA (a server in Node.js and a C++/Qt client). Once registered and authenticated, the user can post messages accessible only when s/he is logged in. You can have a look at them [here](https://github.com/Tashweesh/hpka-example). Sorry if it is still badly documented.
