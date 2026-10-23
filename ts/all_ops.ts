// Cross-language parity: 14 operations (P1-P14), TypeScript (Node crypto).
import crypto from 'node:crypto';

const msg: Buffer = Buffer.from('parity');

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });                                        // P1
export const p2: Buffer = crypto.sign('sha256', msg, rsa.privateKey);                                          // P2
export const p3: Buffer = crypto.publicEncrypt(
  { key: rsa.publicKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, msg);          // P3
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });                                     // P4
export const p4: Buffer = crypto.sign('sha256', msg, ec.privateKey);                                           // P4
const ed = crypto.generateKeyPairSync('ed25519');                                                              // P5
export const p5: Buffer = crypto.sign(null, msg, ed.privateKey);                                               // P5
export const gcm = crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), crypto.randomBytes(12));       // P6 SAFE
export const ecb = crypto.createCipheriv('aes-128-ecb', crypto.randomBytes(16), null);                         // P7 WEAK
export const des3 = crypto.createCipheriv('des-ede3-cbc', crypto.randomBytes(24), crypto.randomBytes(8));      // P8
export const chacha = crypto.createCipheriv(
  'chacha20-poly1305', crypto.randomBytes(32), crypto.randomBytes(12), { authTagLength: 16 });                 // P9 SAFE
export const p10: string = crypto.createHash('md5').update(msg).digest('hex');                                 // P10
export const p11: string = crypto.createHash('sha1').update(msg).digest('hex');                                // P11
export const p12: string = crypto.createHmac('sha1', 'test-only').update(msg).digest('hex');                   // P12
export const p13: Buffer = crypto.pbkdf2Sync('pw', 'salt', 1000, 32, 'sha1');                                  // P13
export const dh = crypto.createDiffieHellman(1024);                                                            // P14
