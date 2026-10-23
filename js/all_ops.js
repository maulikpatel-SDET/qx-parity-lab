// Cross-language parity: 14 operations (P1-P14), Node.js crypto.
const crypto = require('crypto');

const msg = Buffer.from('parity');

const { privateKey: rsaPriv, publicKey: rsaPub } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }); // P1
const p2 = crypto.sign('sha256', msg, rsaPriv);                                                                // P2
const p3 = crypto.publicEncrypt({ key: rsaPub, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, msg); // P3
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });                                     // P4
const p4 = crypto.sign('sha256', msg, ec.privateKey);                                                          // P4
const ed = crypto.generateKeyPairSync('ed25519');                                                              // P5
const p5 = crypto.sign(null, msg, ed.privateKey);                                                              // P5
const gcm = crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), crypto.randomBytes(12));              // P6 SAFE
const ecb = crypto.createCipheriv('aes-128-ecb', crypto.randomBytes(16), null);                                // P7 WEAK
const des3 = crypto.createCipheriv('des-ede3-cbc', crypto.randomBytes(24), crypto.randomBytes(8));             // P8
const chacha = crypto.createCipheriv('chacha20-poly1305', crypto.randomBytes(32), crypto.randomBytes(12), { authTagLength: 16 }); // P9 SAFE
const p10 = crypto.createHash('md5').update(msg).digest('hex');                                                // P10
const p11 = crypto.createHash('sha1').update(msg).digest('hex');                                               // P11
const p12 = crypto.createHmac('sha1', 'test-only').update(msg).digest('hex');                                  // P12
const p13 = crypto.pbkdf2Sync('pw', 'salt', 1000, 32, 'sha1');                                                 // P13
const dh = crypto.createDiffieHellman(1024);                                                                   // P14

module.exports = { p2, p3, p4, p5, gcm, ecb, des3, chacha, p10, p11, p12, p13, dh };
