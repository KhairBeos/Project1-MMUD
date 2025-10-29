"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LEN = 16; // 128-bit
const IV_LEN = 12; // 96-bit (chuẩn tốt cho AES-GCM)
const AUTH_ENTRY_NAME = "__auth_entry__";
const AUTH_PLAINTEXT = "keychain-auth-v1";

/********* Implementation ********/
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

  constructor() {
    // Tạo thuộc tính this.data để lưu thông tin công khai
    this.data = { 
      salt: encodeBuffer(saltBytes), // chuyển đổi salt từ bytes sang base64 để có thể serialize
      kvs: Object.assign({}, kvs) // tạo bản sao của object kvs để tránh thay đổi object gốc
    };

    // Tạo thuộc tính this.secrets để lưu các khóa bí mật
    this.secrets = {
      hmacKeyBytes: new Uint8Array(hmacKeyBytes), // tạo bản sao của khóa HMAC
      aesKeyBytes: new Uint8Array(aesKeyBytes) // tạo bản sao của khóa AES
    };
    
    // Khởi tạo cache cho các CryptoKey
    this._hmacCryptoKey = null; // CryptoKey cho HMAC
    this._aesCryptoKey = null;  // CryptoKey cho AES-GCM
    // Mục đích: tránh phải import khóa nhiều lần, tăng hiệu suất
  };

  //WebCrypto API yêu cầu khóa phải ở dạng CryptoKey để sử dụng
  async _importHmacKeyIfNeeded() {
    //Mục đích: Import khóa HMAC từ raw bytes thành CryptoKey object
    if (this._hmacCryptoKey) return this._hmacCryptoKey; // Kiểm tra cache trước, nếu đã có thì trả về luôn (lazy loading)
    this._hmacCryptoKey = await subtle.importKey(
      "raw", //Định dạng khóa đầu vào là raw bytes
      this.secrets.hmacKeyBytes,
      { name: "HMAC", hash: "SHA-256" }, // Cấu hình thuật toán HMAC với SHA-256
      false, //Khóa không thể extract (bảo mật)
      ["sign", "verify"] //Cho phép ký và xác minh HMAC
    );
    return this._hmacCryptoKey;
  }

  async _importAesKeyIfNeeded() {
    if (this._aesCryptoKey) return this._aesCryptoKey;
    this._aesCryptoKey = await subtle.importKey(
      "raw",
      this.secrets.aesKeyBytes,
      { name: "AES-GCM" }, //Sử dụng AES-GCM mode (có authentication)
      false,
      ["encrypt", "decrypt"] //Cho phép mã hóa và giải mã
    );
    return this._aesCryptoKey;
  }

  //Tính SHA-256 hash của chuỗi, trả về dạng hex
  //Để tạo checksum cho dữ liệu serialized (phát hiện tampering)
  //String → Buffer → SHA-256 → Hex string
  static async _sha256HexOfString(str) {
    const buf = stringToBuffer(str);
    const digest = await subtle.digest("SHA-256", buf);
    const b = new Uint8Array(digest);
    return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
  }

  /* ------------------- Padding helpers ------------------- */

  //Padding password để che giấu độ dài thực
  _padPasswordBytes(passwordBytesUint8) {
    if (passwordBytesUint8.length > MAX_PASSWORD_LENGTH) {
      throw new Error(`Password too long (max ${MAX_PASSWORD_LENGTH})`);
    }
    const total = 1 + MAX_PASSWORD_LENGTH; //[1 byte độ dài][password bytes][random padding]
    const out = new Uint8Array(total);
    out[0] = passwordBytesUint8.length; // Lưu độ dài thực của password
    out.set(passwordBytesUint8, 1);

    //Padding: Thêm bytes ngẫu nhiên để đạt độ dài tối đa
    //Tất cả password đều có cùng độ dài sau padding
    const padLen = MAX_PASSWORD_LENGTH - passwordBytesUint8.length;
    if (padLen > 0) {
      const pad = getRandomBytes(padLen);
      out.set(pad, 1 + passwordBytesUint8.length);
    }
    return out;
  }

  //Khôi phục password gốc từ padded data
  //Đọc độ dài từ byte đầu, cắt đúng số bytes
  _unpadPasswordBytes(paddedUint8) {
    const len = paddedUint8[0];
    return paddedUint8.slice(1, 1 + len);
  }

  /* ------------------- KVS key computation (HMAC of domain) ------------------- */

  //Tạo khóa duy nhất cho mỗi domain bằng HMAC
  async _computeKvsKeyBase64(domain) {
    await this._importHmacKeyIfNeeded();
    const key = this._hmacCryptoKey;
    const dataBuf = stringToBuffer(domain);
    const macBuf = await subtle.sign("HMAC", key, dataBuf); // ArrayBuffer
    // encodeBuffer accepts a buffer -> base64 (lib.js)
    return encodeBuffer(new Uint8Array(macBuf));
  }

  /* ------------------- AES-GCM encrypt/decrypt (AAD = kvsKeyBase64) ------------------- */

  // plainUint8: Uint8Array; aadBase64: string
  async _encryptAesGcm(plainUint8, aadBase64) {
    await this._importAesKeyIfNeeded();
    const iv = getRandomBytes(IV_LEN); //Initialization Vector ngẫu nhiên (12 bytes cho AES-GCM)
    const aad = decodeBuffer(aadBase64); // Additional Authenticated Data (khóa KVS) để xác thực
    //Mã hóa + xác thực trong một bước
    const cipherBuf = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
      this._aesCryptoKey,
      plainUint8
    ); // ArrayBuffer (ciphertext || tag)
    return {
      iv: encodeBuffer(iv),
      ct: encodeBuffer(new Uint8Array(cipherBuf))
    };
  }

  // Giải mã và xác thực dữ liệu
  async _decryptAesGcm(ivBase64, ctBase64, aadBase64) {
    await this._importAesKeyIfNeeded();
    const iv = decodeBuffer(ivBase64);
    const ct = decodeBuffer(ctBase64);
    const aad = decodeBuffer(aadBase64);
    const plainBuf = await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 },
      this._aesCryptoKey,
      ct
    ); //Nếu AAD không khớp, giải mã sẽ thất bại
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
    // 1) Salt: 16 bytes ngẫu nhiên để tăng cường PBKDF2
    const salt = getRandomBytes(SALT_LEN);

    // 2) PBKDF2: Tăng cường password bằng cách lặp 100,000 lần
    const passKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveBits"]);
    const derivedBits = await subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      passKey,
      256
    );
    const masterRaw = new Uint8Array(derivedBits); // 32 bytes

    // 3) Tạo 2 khóa con từ master key
    const masterHmacKey = await subtle.importKey("raw", masterRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const hmacKeyBytesBuf = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("hmac-key")); //Label để tạo khóa HMAC
    const aesKeyBytesBuf  = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("aes-key")); //Label để tạo khóa AES

    const hmacKeyBytes = new Uint8Array(hmacKeyBytesBuf).slice(0, 32); // use 32 bytes
    const aesKeyBytes  = new Uint8Array(aesKeyBytesBuf).slice(0, 32);  // use 32 bytes (AES-256)

    // 4) Tạo instance Keychain với các khóa đã tạo
    const kc = new Keychain(salt, hmacKeyBytes, aesKeyBytes, {});

    // 5) Authentication entry: Tạo entry đặc biệt để verify password
    const authKvsKey = await kc._computeKvsKeyBase64(AUTH_ENTRY_NAME); //AUTH_ENTRY_NAME: Tên cố định "auth_entry"
    const padded = kc._padPasswordBytes(new Uint8Array(stringToBuffer(AUTH_PLAINTEXT))); //AUTH_PLAINTEXT: Text cố định "keychain-auth-v1"
    const enc = await kc._encryptAesGcm(padded, authKvsKey);
    kc.data.kvs[authKvsKey] = { iv: enc.iv, ct: enc.ct };
    // Khi load(), sẽ decrypt entry này để kiểm tra password đúng
    return kc;
  }

  /**
   * Tóm tắt kiến trúc bảo mật:
      Password → Master Key: PBKDF2 với salt và 100,000 iterations
      Master Key → Sub Keys: HMAC với labels khác nhau
      Domain → KVS Key: HMAC của domain name
      Data Encryption: AES-GCM với AAD là KVS key
      Authentication: Entry đặc biệt để verify password khi load
   */

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
    throw "Not Implemented!";
  };

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
    throw "Not Implemented!";
  };

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
    throw "Not Implemented!";
  };

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
    throw "Not Implemented!";
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }
