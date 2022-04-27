const crypto = require('crypto');

const ic = 'S9833756A';

// GENERATING KEY PAIR
const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// FUNCTION TO ENCRYPT
const encrypt = (data, publicKey) => {
  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      openHash: "sha256",
    },
    Buffer.from(data)
  );
  
  console.log('Encrypted data: ', encryptedData.toString("base64"));
  return encryptedData
}

// FUNCTION TO DECRYPT
const decrypt = (data, privateKey) => {
  const decryptedData = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      openHash: "sha256",
    },
    data
  )
  return decryptedData;
}

// Encrypting
const encryptedData = encrypt(ic, publicKey)

// Decrypting
const decryptedData = decrypt(encryptedData, privateKey, "sha256")

console.log('DECRYPTED : ', decryptedData.toString());