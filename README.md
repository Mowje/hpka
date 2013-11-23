# HPKA 0.1, Draft spec

----------------------------------------------------

Written by the Syrian watermelon

Email : [batikhsouri@gmail.com](mailto:batikhsouri@gmail.com)  
Twitter : [@BatikhSouri](https://twitter.com/BatikhSouri)  
Github : [https://github.com/BatikhSouri](https://github.com/BatikhSouri)

## Introduction

HPKA (acronym for HTTP Public Key Authentication) is an extension of the HTTP protocol that aims to authenticate users through public key authentication.

It has some features that are useful when you want to run a distributed, federated network.

It would allow adhoc user authentication, registration, deletion and key rotation

## Technical overview

On each HTTP request, the client appends some headers :

* HPKA-Req: all the details about the action type, username, public key, as described by the protocol below.
* HPKA-Signature: the signature of the HPKA-Req field content

We should note that this solution as it is now is not safe from MITM attacks when not used over HTTPS (or a Tor hidden service). The HPKA-Req contains a timestamp, and as of now the [node-hpka](https://github.com/Tashweesh/node-hpka) implementations rejects payload older than 120 seconds. Hence, in case the connection to the server is not encrypted and/or not authenticated, it is possible that an attacker steals an HPKA and uses it within these 2 minutes... This flaw could be dodged by doing some thourough logging server-side for requests youngest than 2 minutes.

If the headers mentioned above are not present in the HTTP request, then add a "HPKA-Available: 1" header when responding to the client.

If some error occured or some mistake was made in the request, the reponse will have it's status code == 445. In addition to that, it will also carry an additional "HPKA-Error" header; it's value will be just an error number according to the HPKA-Error protocol described below

The signature algorithms that could be used (as of now) in HPKA are :

* [RSA](http://en.wikipedia.org/wiki/RSA_(algorithm\))
* [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
* [ECDSA](http://en.wikipedia.org/wiki/ECDSA)

## Security overview

A similar system (client pub key auth) has been implemented through TLS/SSL client certificates. However, the authentication there is done on TLS/SSL level and not HTTP. Furthermore, client certificates are delivered by the server/service and are signed by a CA on delivery. That last point means that it's not possible to use a client certificate to authenticate on an other server (after a transfer, for example)

The difference here with HPKA is that the users generates his own key pair and signs his public key with his private key on registration. Then he appends specific HTTP headers on each request, each time with a new signature.

Furthermore, this technique brings some advantages over usual username/password authentication methods. For example, if a website using this method is "hacked", the hackers can't hack all users at once by dumping a passwords DB. An other example is that it is probably much harder to hack a specific user account because you would have to compromise the user's device first.

For improved security, the user's key file shoud use a passphrase, so in case the user's device is compromised in any way, the account would be compromised if and only if the attacker was able to decrypt the key file through an expensive password attack (assuming the user wouldn't give him the password...)

Note that the this protocol, as of now, uses the NIST-designed curves for ECDSA signatures. We are aware of the Dual-EC-DRBG NSA backdoor. And some specialists think that there is a good probability that these NIST-designed, NSA-approved curves may be backdoored as well. Aside these, Curve25519 and Ed25519, there aren't lots of other curves used broadly. I plan to extend HPKA for Ed25519/NaCl signatures in upcoming verisons.

**Side note:**  
Further on, I'll say in the small threat model below that a service using HPKA should be hosted somehow securely (HSTS or Tor hidden service). I know there is a contradiction between HSTS and the fact we maybe shouldn't trust CAs as much as we do. But, we can actually do without them in our case : a user will call the same server many times, so certificate pinning of a self-signed cert should be enough. Otherwise, for first time users there isn't a way as much accepted/used as TLS/SSL for authenticating a server.

## Threat model

We describe here our assumptions about the user's computer, and what an attacker can achieve :

* The user acts reasonably. He would not give the password of his key file to an attacker for example
* The user's computer
	* Uses a properly implemented HPKA client
	* Is not infected by malware
* The service uses [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) or a [Tor hidden service](https://www.torproject.org/docs/hidden-services). Equivalently, we must not be able to eavesdrop on a connection between the server and the client
* We assume that the security level provided [DSA](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm), [RSA](https://en.wikipedia.org/wiki/RSA_(algorithm\)) and [ECDSA](https://en.wikipedia.org/wiki/ECDSA) signature schemes is valid. Also we assume that the [most common curves](http://www.secg.org/collateral/sec2_final.pdf) are safe in case we choose to use ECDSA.
* Assumptions about the server:
	* The server has HPKA prorperly implemented
	* The server can refuse a new user registration (attacker could guess usernames then)

## Protocols

### HPKA-Req protocol

__NOTES :__

* Everything is stored in Big Endian
* No encoding is used for key's elements

__The Req payload is constructed as follows :__

* Version number : one byte. Only value for now: 0x01
* UTC Unix Epoch (timestamp since 1-1-1970 00:00:00 UTC, in seconds) (8 bytes long)
* Username.length (one byte)
* Username
* ActionType (one byte)
* Key type : one byte. Values possible are:
	* 0x01 for ECDSA
	* 0x02 for RSA
	* 0x04 for DSA
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

Finally, the built payload is Base64 encoded (because of how HTTP is built, it should be without line breaks). After encoding, this blob is signed by the user's private key (corresponding to the public key info in the blob obviously), using SHA1.

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
0x01  | Malformed request
0x02  | Invalid signature
0x03  | Invalid key
0x04  | Non registered user
0x05  | Username not available (on registration)
0x06  | Forbidden action
0x07  | Unsupported action type
0x08  | Unknown action type
0x09  | Invalid new key (when rotating keys)
0x0A  | Invalid signature for the new key (when rotating keys)
 
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
* [cpp-hpka](https://github.com/Tashweesh/ccp-hpka) : some C++ classes with static methods, letting you building [HPKA client payloads](#hpka-req-protocol). (Doesn't manage the network connections though)

## Example apps

I have written examples that use HPKA (a server in Node.js and a  C++/Qt client). Once registered and authenticated, the user can post messages accessible only when s/he is logged in. You can have a look at them [here](https://github.com/Tashweesh/hpka-example). Sorry if it is still badly documented.