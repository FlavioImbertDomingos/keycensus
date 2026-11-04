const crypto = require('crypto');

const h = crypto.createHash('sha1').update('x').digest('hex');
const tdes = crypto.createCipheriv('des-ede3-cbc', Buffer.alloc(24), Buffer.alloc(8));
const gcm = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
const { publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

async function web() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
}

module.exports = { h, tdes, gcm, publicKey, web };
