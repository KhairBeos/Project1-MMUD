"use strict";

//import { stringify } from "querystring";
/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib.js");
const { webcrypto } = require("crypto");

const subtle = webcrypto.subtle;


const PBKDF2_ITERATIONS = 100000; 
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters
const SALT_LEN = 16;
const IV_LEN = 12; 
const AUTH_ENTRY_NAME = "__auth_entry__";
const AUTH_PLAINTEXT = "keychain-auth-v1";


class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  /** 
  @param {Uint8Array} saltBytes
  @param {Uint8Array} hmacKeyBytes
  @param {Uint8Array} aesKeyBytes
  @param {Object} kvs // map base64(HMAC(domain)) -> { iv: b64, ct: b64 }
  */

  constructor(saltBytes, hmacKeyBytes, aesKeyBytes, kvs) {
   
    this.data = {
      salt: encodeBuffer(saltBytes), 
      kvs: Object.assign({}, kvs), 
    };
    this.secrets = {
      hmacKeyBytes: new Uint8Array(hmacKeyBytes), 
      aesKeyBytes: new Uint8Array(aesKeyBytes), 
    };

    this._hmacCryptoKey = null; 
    this._aesCryptoKey = null; 
    
  }
 
  async _importHmacKeyIfNeeded() {
    
    if (this._hmacCryptoKey) return this._hmacCryptoKey; 
    this._hmacCryptoKey = await subtle.importKey(
      "raw", 
      this.secrets.hmacKeyBytes,
      { name: "HMAC", hash: "SHA-256" }, 
      false, 
      ["sign", "verify"] 
    );
    return this._hmacCryptoKey;
  }

  async _importAesKeyIfNeeded() {
    if (this._aesCryptoKey) return this._aesCryptoKey;
    this._aesCryptoKey = await subtle.importKey(
      "raw",
      this.secrets.aesKeyBytes,
      { name: "AES-GCM" }, 
      false,
      ["encrypt", "decrypt"] 
    );
    return this._aesCryptoKey;
  }

  static async _sha256HexOfString(str) {
    const buf = stringToBuffer(str);
    const digest = await subtle.digest("SHA-256", buf);
    const b = new Uint8Array(digest);
    return Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  }

  _padPasswordBytes(passwordBytesUint8) {
    if (passwordBytesUint8.length > MAX_PASSWORD_LENGTH) {
      throw new Error(`Password too long (max ${MAX_PASSWORD_LENGTH})`);
    }
    const total = 1 + MAX_PASSWORD_LENGTH; 
    const out = new Uint8Array(total);
    out[0] = passwordBytesUint8.length; 
    out.set(passwordBytesUint8, 1);

    const padLen = MAX_PASSWORD_LENGTH - passwordBytesUint8.length;
    if (padLen > 0) {
      const pad = getRandomBytes(padLen);
      out.set(pad, 1 + passwordBytesUint8.length);
    }
    return out;
  }

  _unpadPasswordBytes(paddedUint8) {
    const len = paddedUint8[0];
    return paddedUint8.slice(1, 1 + len);
  }

  async _computeKvsKeyBase64(domain) {
    await this._importHmacKeyIfNeeded();
    const key = this._hmacCryptoKey;
    const dataBuf = stringToBuffer(domain);
    const macBuf = await subtle.sign("HMAC", key, dataBuf); 
    return encodeBuffer(new Uint8Array(macBuf));
  }

  async _encryptAesGcm(plainUint8, aadBase64) {
    await this._importAesKeyIfNeeded();
    const iv = getRandomBytes(IV_LEN); 
    const aad = decodeBuffer(aadBase64); 
    const cipherBuf = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
      this._aesCryptoKey,
      plainUint8
    ); 
    return {
      iv: encodeBuffer(iv),
      ct: encodeBuffer(new Uint8Array(cipherBuf)),
    };
  }

  async _decryptAesGcm(ivBase64, ctBase64, aadBase64) {
    await this._importAesKeyIfNeeded();
    const iv = decodeBuffer(ivBase64);
    const ct = decodeBuffer(ctBase64);
    const aad = decodeBuffer(aadBase64);
    const plainBuf = await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
      this._aesCryptoKey,
      ct
    ); 
    return new Uint8Array(plainBuf);
  }

  /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(password) {
    const salt = getRandomBytes(SALT_LEN);
    const passKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      passKey,
      256
    );
    const masterRaw = new Uint8Array(derivedBits); 
    const masterHmacKey = await subtle.importKey(
      "raw",
      masterRaw,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const hmacKeyBytesBuf = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("hmac-key")
    ); 
    const aesKeyBytesBuf = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("aes-key")
    ); 

    const hmacKeyBytes = new Uint8Array(hmacKeyBytesBuf).slice(0, 32); 
    const aesKeyBytes = new Uint8Array(aesKeyBytesBuf).slice(0, 32); 
    const kc = new Keychain(salt, hmacKeyBytes, aesKeyBytes, {});
    const authKvsKey = await kc._computeKvsKeyBase64(AUTH_ENTRY_NAME); 
    const padded = kc._padPasswordBytes(
      new Uint8Array(stringToBuffer(AUTH_PLAINTEXT))
    ); 
    const enc = await kc._encryptAesGcm(padded, authKvsKey);
    kc.data.kvs[authKvsKey] = { iv: enc.iv, ct: enc.ct };
    return kc;
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    const obj = JSON.parse(repr);
    const saltBytes = decodeBuffer(obj.salt);
    const serializedKvs = obj.kvs || {};
    const serializedAuth = obj.auth;
    if (trustedDataCheck) {
      const checksum = await Keychain._sha256HexOfString(repr);
      if (trustedDataCheck !== checksum)
        throw new Error("Integrity check failed!");
    }
    const passKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      passKey,
      256
    );
    const masterRaw = new Uint8Array(derivedBits); 
    const masterHmacKey = await subtle.importKey(
      "raw",
      masterRaw,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const hmacKeyBytesBuf = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("hmac-key")
    ); 
    const aesKeyBytesBuf = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("aes-key")
    ); 

    const hmacKeyBytes = new Uint8Array(hmacKeyBytesBuf).slice(0, 32); 
    const aesKeyBytes = new Uint8Array(aesKeyBytesBuf).slice(0, 32); 

    const kvsWithAuth = Object.assign({}, serializedKvs);
    const tempKeychain = new Keychain(saltBytes, hmacKeyBytes, aesKeyBytes, {});
    const authKvsKey = await tempKeychain._computeKvsKeyBase64(AUTH_ENTRY_NAME);
    kvsWithAuth[authKvsKey] = serializedAuth;
    const kc = new Keychain(saltBytes, hmacKeyBytes, aesKeyBytes, kvsWithAuth);
    const authEnc = kc.data.kvs[authKvsKey];
    if (!authEnc) throw new Error("Auth entry missing.");
    try {
      const plain = await kc._decryptAesGcm(authEnc.iv, authEnc.ct, authKvsKey);
      const unpadded = kc._unpadPasswordBytes(plain);
      const text = bufferToString(unpadded);
      if (text !== AUTH_PLAINTEXT) throw new Error("Invalid password.");
    } catch (e) {
      throw new Error("Invalid password — authentication failed.");
    }

    return kc;
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity.
   *
   * Return Type: array
   */
  async dump() {
    const authKey = await this._computeKvsKeyBase64(AUTH_ENTRY_NAME);
    const authEntry = this.data.kvs[authKey];

    const sanitizedKvs = Object.assign({}, this.data.kvs);
    delete sanitizedKvs[authKey];

    const payload = {
      salt: this.data.salt,
      kvs: sanitizedKvs,
      auth: authEntry,
    };

    const jsonString = JSON.stringify(payload);
    const checksum = await Keychain._sha256HexOfString(jsonString);
    return [jsonString, checksum];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    const kvsKey = await this._computeKvsKeyBase64(name);
    const record = this.data.kvs[kvsKey];
    if (!record) return null;
    try {
      const plain = await this._decryptAesGcm(record.iv, record.ct, kvsKey);
      const unpadded = this._unpadPasswordBytes(plain);
      return bufferToString(unpadded);
    } catch (e) {
      throw new Error("Tampering detected or invalid ciphertext!");
    }
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(name, value) {
    const kvsKey = await this._computeKvsKeyBase64(name);
    const padded = this._padPasswordBytes(
      new Uint8Array(stringToBuffer(value))
    );
    const enc = await this._encryptAesGcm(padded, kvsKey);
    this.data.kvs[kvsKey] = { iv: enc.iv, ct: enc.ct };
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    const kvsKey = await this._computeKvsKeyBase64(name);
    if (this.data.kvs.hasOwnProperty(kvsKey)) {
      delete this.data.kvs[kvsKey];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
