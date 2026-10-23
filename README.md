# qx-parity-lab  (Cross-language parity)

The SAME 14 crypto operations, written the same way, in all 5 supported file types:
Python (.py), Java (.java), Go (.go), Node (.js), TypeScript (.ts).

Goal: scan all 5, then compare. A correct scanner gives the SAME verdict for the same
operation in every language. Any row where one language is detected and another is not,
or where one is 'Safe' and another 'Vulnerable', is an inconsistency bug.

Operation list (P1-P14):
 P1  RSA-2048 key generation        (Vulnerable)
 P2  RSA-2048 signature SHA-256     (Vulnerable)
 P3  RSA-OAEP encryption            (Vulnerable, HNDL)
 P4  ECDSA P-256 key + sign         (Vulnerable)
 P5  Ed25519 key + sign             (Vulnerable)
 P6  AES-256-GCM encrypt            (SAFE)
 P7  AES-128-ECB encrypt            (WEAK - must flag mode)
 P8  3DES encrypt                   (Vulnerable/weak)
 P9  ChaCha20-Poly1305 encrypt      (SAFE)
 P10 MD5 hash                       (Broken)
 P11 SHA-1 hash                     (Weak)
 P12 HMAC-SHA1                      (Weak)
 P13 PBKDF2-HMAC-SHA1, 1000 iters   (Weak KDF)
 P14 Diffie-Hellman / ECDH          (Vulnerable)
ALL KEYS AND SECRETS ARE TEST VALUES.
