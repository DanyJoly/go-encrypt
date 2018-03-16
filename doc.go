/*
Package encrypt will encrypt and decrypt data securely using the same password for both operations.

It was developed specifically for safe file encryption.

WARNING: These functions are not suitable for client-server communication protocols. See details bellow.

Implementation details

The author used VeraCrypt and TrueCrypt as inspirations for the implementation. Unlike these two products, we don't
need to encrypt whole dynamic filesystems, or hidden volumes so many steps are greatly simplified. Support was also
added for more advanced password hash, such as adding Argon2 password hashing on top of PBKDF2 used by VeraCrypt.

Data encryption

Just like VeraCrypt and BitLocker (Microsoft), we rely on AES-256 in XTS mode symmetric-key encryption.  It's a modern
block cipher developed for disk encryption that is a bit less malleable than the more traditional CBC mode.

While AES provides fast content encryption, it's not a complete solution. AES keys are fixed-length 256 bits and unlike
user passwords, they must have excellent entropy.

Password Hashing

To create fixed-length keys with excellent entropy, we rely on password hash functions. These are built to spread the
entropy to the full length of the key and it gives ample protection against password brute force attacks.

Rainbow table attacks (precalculated hashes) are mitigated with a 512 bits random password salt. The salt can be public,
as long as the password stays private.

For password hashing, we joint a battle-tested algorithm, PBKDF2, with a next gen password hash: Argon2id. Argon2 helps
protect against GPU-based attacks, but is a very recent algo. If flaws are ever discovered in it, we have a fallback
algorithm. Settings for both password hash functions are secure and stronger the usually recommended settings as of
2018. This does mean that our password hashing function is very expensive (benchmarked around 1s on my desktop
computer), but this is not usually an issue for tasks such as file encryption or decryption and the added protection is
significant.

Protection Against Tampering

AES with XTS mode doesn't prevent an attacker from maliciously modifying the encrypted content.
To ensure that we catch these cases, we calculate a SHA-512 digest on the plain content and we encrypt it too.

Once we decrypt that content, if the header matches, it's likely (although not 100% certain) that the password is
correct. If the header matches, but the SHA-512 digest doesn't match, it's likely that the data has been tampered with
and we reject it.

Password Validation

Finally, decrypting with the AES cypher will always seem to work, whether the password is correct or not. The only
difference is that the output will be valid content or garbage. To make the distinction between a bad password and
tampered data in a user-friendly way, we include a small header in the plain content ('GOODPW').

Security notes

(1) These encryption utilities are not suitable as a secure client-server communication protocol, which must deal with
additional security constraints. For example, depending on how a server would use it, it could be vulnerable to padding
oracle attacks.

(2) We store and cache passwords and AES keys in memory, which can then also be swapped to disk by the OS. Encrypter
and Decrypter will erase the password and EAS when they are closed explicitly, but this is weak defense in depth only
so there is an assumption that the attacker doesn't have memory read access.

Data Format

  (64 bytes) salt
  (? bytes)  Encrypted content

  Encrypted content format:
  (6 bytes)  Magic bytes ('GOODPW')
  (1 byte)   Protocol version
  (1 byte)   Padding length (0 to 16 bytes)
  (? bytes)  Padding
  (? bytes)  plain content

Notes on Data Format

We store the salt along with the data.This is because these utilities are geared toward file encryption and its
impractical to store it separately.

References

AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

PBKDF2: https://en.wikipedia.org/wiki/PBKDF2

Argon2: https://en.wikipedia.org/wiki/Argon2

VeraCrypt: https://veracrypt.fr

TrueCrypt implementations: http://blog.bjrn.se/2008/01/truecrypt-explained.html

Oracle attack: https://en.wikipedia.org/wiki/Oracle_attack

NIST Digital Security Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html
*/
package encrypt
