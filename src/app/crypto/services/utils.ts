import CryptoJS from 'crypto-js';
import { DriveItemData } from '../../drive/types';
import { aes, items as itemUtils } from '@internxt/lib';
import { AdvancedSharedItem } from '../../share/types';
import { Buffer } from 'buffer';
import crypto from 'crypto';
import { createSHA512, createSHA256, argon2id, createHMAC, sha256, sha512, ripemd160 } from 'hash-wasm';

const AES_IV_LEN = 16;
const AES_ALG = 'aes-256-gcm';

/**
 * Argon2id parameters taken from RFC9106 (variant for memory-constrained environments)
 * @constant
 * @type {number}
 * @default
 */
const ARGON2ID_PARALLELISM = 4;
const ARGON2ID_ITERATIONS = 3;
const ARGON2ID_MEMORY = 65536;
const ARGON2ID_TAG_LEN = 32;
const ARGON2ID_SALT_LEN = 16;

interface PassObjectInterface {
  salt?: string | null;
  password: string;
}

/**
 * Computes hmac-sha512
 * @param {string} encryptionKeyHex - The hmac key in HEX format
 * @param {string} dataArray - The input array of data
 * @returns {Promise<string>} The result of applying hmac-sha512 to the array of data.
 */
function getHmacSha512FromHexKey(encryptionKeyHex: string, dataArray: string[] | Buffer[]): Promise<string> {
  const encryptionKey = Buffer.from(encryptionKeyHex, 'hex');
  return getHmacSha512(encryptionKey, dataArray);
}

/**
 * Computes hmac-sha512
 * @param {Buffer} encryptionKey - The hmac key
 * @param {string} dataArray - The input array of data
 * @returns {Promise<string>} The result of applying hmac-sha512 to the array of data.
 */
async function getHmacSha512(encryptionKey: Buffer, dataArray: string[] | Buffer[]): Promise<string> {
  const hashFunc = createSHA512();
  const hmac = await createHMAC(hashFunc, encryptionKey);
  hmac.init();
  for (const data of dataArray) {
    hmac.update(data);
  }
  return hmac.digest();
}

/**
 * Computes sha256
 * @param {string} data - The input data
 * @returns {Promise<string>} The result of applying sha256 to the data.
 */
function getSha256(data: string): Promise<string> {
  return sha256(data);
}

/**
 * Creates sha256 hasher
 * @returns {Promise<IHasher>} The sha256 hasher
 */
function getSha256Hasher() {
  return createSHA256();
}

/**
 * Computes sha512
 * @param {string} dataHex - The input data in HEX format
 * @returns {Promise<string>} The result of applying sha512 to the data.
 */
function getSha512FromHex(dataHex: string): Promise<string> {
  const data = Buffer.from(dataHex, 'hex');
  return sha512(data);
}

/**
 * Computes ripmd160
 * @param {string} dataHex - The input data in HEX format
 * @returns {Promise<string>} The result of applying ripmd160 to the data.
 */
function getRipemd160FromHex(dataHex: string): Promise<string> {
  const data = Buffer.from(dataHex, 'hex');
  return ripemd160(data);
}

/**
 * Computes Argon2 and outputs the result in HEX format
 * @param {string} password - The password
 * @param {number} salt - The salt
 * @param {number} [parallelism=ARGON2ID_PARALLELISM] - The parallelism degree
 * @param {number}[iterations=ARGON2ID_ITERATIONS] - The number of iterations to perform
 * @param {number}[memorySize=ARGON2ID_MEMORY] - The number of KB of memeory to use
 * @param {number} [hashLength=ARGON2ID_TAG_LEN] - The desired output length
 * @param {'hex'|'binary'|'encoded'} [outputType="encoded"] - The output type
 * @returns {Promise<string>} The result of Argon2
 */
function getArgon2(
  password: string,
  salt: string,
  parallelism: number = ARGON2ID_PARALLELISM,
  iterations: number = ARGON2ID_ITERATIONS,
  memorySize: number = ARGON2ID_MEMORY,
  hashLength: number = ARGON2ID_TAG_LEN,
  outputType: 'hex' | 'binary' | 'encoded' = 'encoded',
): Promise<string> {
  return argon2id({
    password,
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength,
    outputType,
  });
}

// Method to hash password. If salt is passed, use it, in other case use crypto lib for generate salt
function passToHash(passObject: PassObjectInterface): { salt: string; hash: string } {
  const salt = passObject.salt ? CryptoJS.enc.Hex.parse(passObject.salt) : CryptoJS.lib.WordArray.random(128 / 8);
  const hash = CryptoJS.PBKDF2(passObject.password, salt, { keySize: 256 / 32, iterations: 10000 });
  const hashedObjetc = {
    salt: salt.toString(),
    hash: hash.toString(),
  };
  return hashedObjetc;
}

/**
 * AES plain text encryption
 * @param {string} textToEncrypt - The plain text
 * @returns {string} The ciphertext
 */
async function encryptText(textToEncrypt: string): Promise<string> {
  return encryptTextWithKey(textToEncrypt, process.env.REACT_APP_CRYPTO_SECRET);
}

/**
 * AES plain text decryption
 * @param {string} encryptedText - The ciphertext
 * @returns {string} The plain text
 */
async function decryptText(encryptedText: string): Promise<string> {
  return decryptTextWithKey(encryptedText, process.env.REACT_APP_CRYPTO_SECRET);
}

/**
 * AES plain text encryption with the given password (identical to what CryptoJS does)
 * @param {string} textToEncrypt - The plain text
 * @param {string} keyToEncrypt - The password
 * @returns {string} The ciphertext
 */
async function encryptTextWithKey(textToEncrypt: string, keyToEncrypt: string): Promise<string> {
  const salt = crypto.randomBytes(ARGON2ID_SALT_LEN);
  const iv = crypto.randomBytes(AES_IV_LEN);
  const key = await getArgon2(keyToEncrypt, salt.toString('hex'), undefined, undefined, undefined, undefined, 'hex');
  const cipher = crypto.createCipheriv(AES_ALG, Buffer.from(key, 'hex'), iv);
  const result = Buffer.concat([salt, iv, cipher.update(textToEncrypt), cipher.final(), cipher.getAuthTag()]).toString(
    'hex',
  );
  return result;
}

/**
 * AES plain text decryption with the given password (identical to what CryptoJS does)
 * @param {string} encryptedText - The ciphertext
 * @param {string} keyToEncrypt - The password
 * @returns {string} The plain text
 */
async function decryptTextWithKey(encryptedText: string, keyToDecrypt: string): Promise<string> {
  if (!keyToDecrypt) {
    return Promise.reject(new Error('No key defined. Check .env file'));
  }
  let result;

  // if starts with Salted_ => old CryptoJS
  if (encryptedText.startsWith('53616c7465645f')) {
    result = decryptTextWithKeyCryptoJs(encryptedText, keyToDecrypt);
  } else {
    const cipher = Buffer.from(encryptedText, 'hex');
    const salt = cipher.subarray(0, ARGON2ID_SALT_LEN).toString('hex');
    const iv = cipher.subarray(ARGON2ID_SALT_LEN, ARGON2ID_SALT_LEN + AES_IV_LEN);
    const tag = cipher.subarray(cipher.length - 16);
    const key = await getArgon2(keyToDecrypt, salt, undefined, undefined, undefined, undefined, 'hex');
    const decipher = crypto.createDecipheriv(AES_ALG, Buffer.from(key, 'hex'), iv);
    decipher.setAuthTag(tag);
    result = decipher.update(cipher.subarray(ARGON2ID_SALT_LEN + AES_IV_LEN, cipher.length - 16));
    result = Buffer.concat([result, decipher.final()]);
    result = result.toString('utf8');
  }

  return result;
}

/**
 * AES plain text decryption with the given password (identical to what CryptoJS does)
 * @param {string} encryptedText - The ciphertext
 * @param {string} keyToEncrypt - The password
 * @returns {string} The plain text
 */
function decryptTextWithKeyCryptoJs(encryptedText: string, keyToDecrypt: string): string {
  const cypher = Buffer.from(encryptedText, 'hex');

  const salt = cypher.subarray(8, 16);
  const password = Buffer.concat([Buffer.from(keyToDecrypt, 'binary'), salt]);
  const md5Hashes: Buffer[] = [];
  let digest = password;
  for (let i = 0; i < 3; i++) {
    md5Hashes[i] = crypto.createHash('md5').update(digest).digest();
    digest = Buffer.concat([md5Hashes[i], password]);
  }
  const key = Buffer.concat([md5Hashes[0], md5Hashes[1]]);
  const iv = md5Hashes[2];
  const contents = cypher.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  let result = decipher.update(contents);
  result = Buffer.concat([result, decipher.final()]);

  return result.toString('utf8');
}

function excludeHiddenItems(items: DriveItemData[]): DriveItemData[] {
  return items.filter((item) => !itemUtils.isHiddenItem(item));
}

function renameFile(file: File, newName: string): File {
  return new File([file], newName);
}

const getItemPlainName = (item: DriveItemData | AdvancedSharedItem) => {
  if (item.plainName && item.plainName.length > 0) {
    return item.plainName;
  }
  try {
    if (item.isFolder || item.type === 'folder') {
      return aes.decrypt(item.name, `${process.env.REACT_APP_CRYPTO_SECRET2}-${item.parentId}`);
    } else {
      return aes.decrypt(item.name, `${process.env.REACT_APP_CRYPTO_SECRET2}-${item.folderId}`);
    }
  } catch (err) {
    //Decrypt has failed because item.name is not encrypted
    return item.name;
  }
};

export {
  passToHash,
  encryptText,
  decryptText,
  encryptTextWithKey,
  decryptTextWithKey,
  excludeHiddenItems,
  renameFile,
  getItemPlainName,
  getHmacSha512FromHexKey,
  getHmacSha512,
  getSha256,
  getSha256Hasher,
  getSha512FromHex,
  getRipemd160FromHex,
  getArgon2,
};
