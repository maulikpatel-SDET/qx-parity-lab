"""Cross-language parity: 14 operations (P1-P14), Python / cryptography + hashlib + hmac."""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

msg = b"parity"

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)                      # P1
p2 = rsa_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())                                   # P2
p3 = rsa_key.public_key().encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),        # P3
                                                    algorithm=hashes.SHA256(), label=None))
ec_key = ec.generate_private_key(ec.SECP256R1())                                             # P4
p4 = ec_key.sign(msg, ec.ECDSA(hashes.SHA256()))                                             # P4
ed = ed25519.Ed25519PrivateKey.generate()                                                   # P5
p5 = ed.sign(msg)                                                                            # P5
p6 = AESGCM(AESGCM.generate_key(256)).encrypt(os.urandom(12), msg, None)                     # P6 SAFE
_ecb = Cipher(algorithms.AES(os.urandom(16)), modes.ECB()).encryptor()                       # P7 WEAK
p7 = _ecb.update(msg.ljust(16)) + _ecb.finalize()
_des = Cipher(TripleDES(os.urandom(24)), modes.CBC(os.urandom(8))).encryptor()               # P8
p8 = _des.update(msg.ljust(8)) + _des.finalize()
p9 = ChaCha20Poly1305(ChaCha20Poly1305.generate_key()).encrypt(os.urandom(12), msg, None)    # P9 SAFE
p10 = hashlib.md5(msg).hexdigest()                                                           # P10
p11 = hashlib.sha1(msg).hexdigest()                                                          # P11
p12 = hmac.new(b"test-only", msg, hashlib.sha1).hexdigest()                                  # P12
p13 = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=b"salt", iterations=1000).derive(b"pw")  # P13
_dh = dh.generate_parameters(generator=2, key_size=1024).generate_private_key()              # P14
p14 = _dh.public_key()
