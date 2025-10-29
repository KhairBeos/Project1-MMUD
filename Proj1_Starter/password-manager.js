"use strict";

/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters

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
  constructor() {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
    };

    throw "Not Implemented!";
  }

  /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(password) {
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    throw "Not Implemented!";
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
    // Bước 1: Tính HMAC(domain) để tra khóa trong KVS
    const nameBuf = stringToBuffer(name);
    const rawHmac = await subtle.sign("HMAC", this.hmacKey, nameBuf);
    const domainKey = encodeBuffer(rawHmac); // Base64 key

    // Bước 2: Kiểm tra xem có tồn tại trong KVS không
    const record = this.kvs[domainKey];
    if (!record) {
      return null; // Không có domain này
    }

    // Bước 3: Giải mã mật khẩu bằng AES-GCM
    try {
      const iv = decodeBuffer(record.iv); // IV dạng buffer
      const ciphertext = decodeBuffer(record.ciphertext); // ciphertext dạng buffer

      const decParams = {
        name: "AES-GCM",
        iv: iv,
        additionalData: rawHmac, // liên kết domain -> chống swap attack
        tagLength: 128,
      };

      // Giải mã
      const decryptedBuf = await subtle.decrypt(
        decParams,
        this.aesKey,
        ciphertext
      );
      let decryptedStr = bufferToString(decryptedBuf);

      // Bước 4: Bỏ padding '\0' ở cuối (đã thêm trong hàm set)
      decryptedStr = decryptedStr.replace(/\0+$/g, "");

      return decryptedStr;
    } catch (e) {
      // Nếu giải mã lỗi (swap attack / sai key / dữ liệu bị chỉnh sửa)
      throw "Tampering detected or invalid ciphertext!";
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
    // constants
    const MAX_PW_LEN = 64; // theo đề: tối đa 64 ký tự
    const AES_GCM_IV_LEN = 12; // 96-bit IV chuẩn cho AES-GCM

    // 1) Tính HMAC(domain) -> raw bytes và key dạng Base64 để làm khóa trong KVS
    const nameBuf = stringToBuffer(name);
    const rawHmac = await subtle.sign("HMAC", this.hmacKey, nameBuf); // ArrayBuffer
    const domainKey = encodeBuffer(rawHmac); // Base64 string dùng làm key trong JS object

    // 2) Pad value tới độ dài cố định (64) để không rò rỉ độ dài
    let paddedValue = value;
    if (paddedValue.length > MAX_PW_LEN) {
      // theo đề có thể giả định max length <=64; nếu >64 thì cắt bớt
      paddedValue = paddedValue.slice(0, MAX_PW_LEN);
    } else if (paddedValue.length < MAX_PW_LEN) {
      // pad bằng null char '\0' (khi giải mã ta sẽ trim)
      paddedValue = paddedValue + "\0".repeat(MAX_PW_LEN - paddedValue.length);
    }
    const plaintextBuf = stringToBuffer(paddedValue);

    // 3) Tạo IV ngẫu nhiên
    const iv = getRandomBytes(AES_GCM_IV_LEN); // trả về ArrayBuffer / Uint8Array

    // 4) Mã hoá với AES-GCM; dùng rawHmac (ArrayBuffer) làm associatedData (AAD)
    const encParams = {
      name: "AES-GCM",
      iv: iv,
      additionalData: rawHmac, // liên kết ciphertext với domain HMAC -> chống swap
      tagLength: 128,
    };

    const cipherBuf = await subtle.encrypt(
      encParams,
      this.aesKey,
      plaintextBuf
    );

    // 5) Lưu vào KVS: lưu ciphertext và iv dưới dạng Base64 (dễ serialize)
    this.kvs[domainKey] = {
      ciphertext: encodeBuffer(cipherBuf),
      iv: encodeBuffer(iv),
      // (có thể thêm timestamp/version nếu cần cho rollback protection)
    };

    // không cần return (void), nhưng trả về để thuận tiện có thể trả về true/false nếu muốn
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
    const nameBuf = stringToBuffer(name);
    const hmacDomain = await subtle.sign("HMAC", this.hmacKey, nameBuf);
    const domainKey = encodeBuffer(hmacDomain); // chuyển sang Base64 để dùng làm key

    // Bước 2: Kiểm tra xem key này có trong KVS không
    if (this.kvs.hasOwnProperty(domainKey)) {
      delete this.kvs[domainKey]; // Xóa bản ghi
      return true;
    } else {
      return false; // Không tồn tại -> trả về false
    }
  }
}

module.exports = { Keychain };
