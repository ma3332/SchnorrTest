const Buffer = require("safe-buffer").Buffer;
const BigInteger = require("bigi");
const randomBytes = require("random-bytes");
const randomBuffer = (len) => Buffer.from(randomBytes.sync(len));
const schnorr = require("bip-schnorr");
const convert = schnorr.convert;
const muSig = schnorr.muSig;
const math = schnorr.math;
const sha256 = require("js-sha256");
const BN = require("bn.js");
var EC = require("elliptic").ec;
const curve = new EC("secp256k1");

// ------ utils -------
const POOL64 = Buffer.allocUnsafe(64);

function hashConcatMsg(msg, r) {
  const R = r.toArrayLike(Buffer, "be", 32);
  const B = POOL64;
  R.copy(B, 0);
  msg.copy(B, 32);
  return new BN(sha256.digest(B));
}

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function verify(msgHash, signature, publicKeyString) {
  const r_temp = new BN(signature.r.slice(0, 64), "hex");
  const s_temp = new BN(signature.s, "hex");

  const h = new BN(Buffer.from(msgHash, "hex"));

  if (h.gte(curve.n)) throw new Error("Invalid hashConcatMsg.");
  if (h.isZero()) throw new Error("Invalid hashConcatMsg.");
  if (s_temp.gte(new BN(curve.n))) throw new Error("Invalid S value.");

  if (r_temp.gt(curve.curve.p)) throw new Error("Invalid R value.");

  const publicKeyBN = new BN(publicKeyString, "hex");
  let pubCompress;
  if (publicKeyBN.isOdd()) {
    pubCompress = "03" + publicKeyString.slice(0, 64);
  } else {
    pubCompress = "02" + publicKeyString.slice(0, 64);
  }
  const pub_point = curve.curve.decodePoint(Buffer.from(pubCompress, "hex"));

  const r_BN = new BN(signature.r, "hex");
  let r_compress;
  if (r_BN.isOdd()) {
    r_compress = "03" + signature.r.slice(0, 64);
  } else {
    r_compress = "02" + signature.r.slice(0, 64);
  }
  const r_point = curve.curve.decodePoint(Buffer.from(r_compress, "hex"));

  const l = pub_point.mul(h);
  const verify_1 = curve.g.mul(s_temp);
  const verify_2 = r_point.add(l);

  //   if (r_verify_2.y.isOdd()) throw new Error("Odd R value.");

  if (verify_1.getX().toString(16) == verify_2.getX().toString(16)) {
    return true;
  } else {
    return false;
  }
}

// ---------------- Msg Hash -------------------
const msg = "tuananh";
const msgHash = sha256.digest(Buffer.from(msg, "ascii"));

// ----------- Private Key & Public Key Generation in Individual Card ------------
const privateKey_1 = Buffer.from(
  "dce71358bf6d57dffaf8ac422ea972dca65badd2ce21b585803ea3075b7de388",
  "hex"
);

const privateKey_2 = Buffer.from(
  "7a12e8a7c1b18a47df7ae73f89931af32483743ab522e2003b6b65727e4a31bd",
  "hex"
);

const privateKey_3 = Buffer.from(
  "3feb2c96761f96431630b089ae5d1767325ca0aaa48e98cc87d2976bba2d8110",
  "hex"
);

const privateKey1_BN = new BN(privateKey_1, "hex");
const privateKey2_BN = new BN(privateKey_2, "hex");
const privateKey3_BN = new BN(privateKey_3, "hex");

const publicKey1 = curve.g.mul(privateKey1_BN);
const publicKey2 = curve.g.mul(privateKey2_BN);
const publicKey3 = curve.g.mul(privateKey3_BN);

const publicKeyHexString1 = toHexString(publicKey1.encode()).slice(2);
const publicKeyHexString2 = toHexString(publicKey2.encode()).slice(2);
const publicKeyHexString3 = toHexString(publicKey3.encode()).slice(2);

// --------- Calculate Sum of PublicKey (In App) ------------
const publicKey1_BN = new BN(publicKeyHexString1, "hex");
const publicKey2_BN = new BN(publicKeyHexString2, "hex");
const publicKey3_BN = new BN(publicKeyHexString3, "hex");

let pubCompress_1;
if (publicKey1_BN.isOdd()) {
  pubCompress_1 = "03" + publicKeyHexString1.slice(0, 64);
} else {
  pubCompress_1 = "02" + publicKeyHexString1.slice(0, 64);
}

let pubCompress_2;
if (publicKey2_BN.isOdd()) {
  pubCompress_2 = "03" + publicKeyHexString2.slice(0, 64);
} else {
  pubCompress_2 = "02" + publicKeyHexString2.slice(0, 64);
}

let pubCompress_3;
if (publicKey3_BN.isOdd()) {
  pubCompress_3 = "03" + publicKeyHexString3.slice(0, 64);
} else {
  pubCompress_3 = "02" + publicKeyHexString3.slice(0, 64);
}

const publicKey1_point = curve.curve.decodePoint(
  Buffer.from(pubCompress_1, "hex")
);
const publicKey2_point = curve.curve.decodePoint(
  Buffer.from(pubCompress_2, "hex")
);
const publicKey3_point = curve.curve.decodePoint(
  Buffer.from(pubCompress_3, "hex")
);

const pubKeySum = publicKey1_point.add(publicKey2_point).add(publicKey3_point);

const pubKeySumHexString = toHexString(pubKeySum.encode()).slice(2);

// ------- Calculate hash Concatenate Msg in App ---------
const hashConcat = new BN(Buffer.from(msgHash, "hex"));

// ------- Calculate all individual r in Card ---------
const rand_Hex_1 = Array(64)
  .fill()
  .map(() => Math.round(Math.random() * 0xf).toString(16))
  .join("");
const rand_BN_1 = new BN(rand_Hex_1, "hex");
if (rand_BN_1.gte(curve.n)) {
  throw new Error("Invalid random number 1");
}
const r_1 = curve.g.mul(rand_BN_1);
const r_output_1 = toHexString(r_1.encode()).slice(2);

const rand_Hex_2 = Array(64)
  .fill()
  .map(() => Math.round(Math.random() * 0xf).toString(16))
  .join("");
const rand_BN_2 = new BN(rand_Hex_2, "hex");
if (rand_BN_2.gte(curve.n)) {
  throw new Error("Invalid random number 1");
}
const r_2 = curve.g.mul(rand_BN_2);
const r_output_2 = toHexString(r_2.encode()).slice(2);

const rand_Hex_3 = Array(64)
  .fill()
  .map(() => Math.round(Math.random() * 0xf).toString(16))
  .join("");
const rand_BN_3 = new BN(rand_Hex_3, "hex");
if (rand_BN_3.gte(curve.n)) {
  throw new Error("Invalid random number 1");
}
const r_3 = curve.g.mul(rand_BN_3);
const r_output_3 = toHexString(r_3.encode()).slice(2);

// ------- Calculate all individual s in Card -------
let s_1 = rand_BN_1.add(hashConcat.mul(privateKey1_BN)); // (k + prk*e) mod n
const s_output_1 = s_1.toString(16);

let s_2 = rand_BN_2.add(hashConcat.mul(privateKey2_BN)); // (k + prk*e) mod n
const s_output_2 = s_2.toString(16);

let s_3 = rand_BN_3.add(hashConcat.mul(privateKey3_BN)); // (k + prk*e) mod n
const s_output_3 = s_3.toString(16);

// ------ Partial Signature --------
const signature_1 = { r: r_output_1, s: s_output_1 };
const signature_2 = { r: r_output_2, s: s_output_2 };
const signature_3 = { r: r_output_3, s: s_output_3 };

// ------- Sum Signature in App --------
const s_BN_1 = new BN(signature_1.s, "hex");
const s_BN_2 = new BN(signature_2.s, "hex");
const s_BN_3 = new BN(signature_3.s, "hex");

let s_BN_sum = s_BN_1.add(s_BN_2).add(s_BN_3);
s_BN_sum = s_BN_sum.umod(curve.n);
const s_sum_output = s_BN_sum.toString(16);

const r_BN_1 = new BN(signature_1.r, "hex");
const r_BN_2 = new BN(signature_2.r, "hex");
const r_BN_3 = new BN(signature_3.r, "hex");

let r_compress_1;
if (r_BN_1.isOdd()) {
  r_compress_1 = "03" + signature_1.r.slice(0, 64);
} else {
  r_compress_1 = "02" + signature_1.r.slice(0, 64);
}
const r_point_1 = curve.curve.decodePoint(Buffer.from(r_compress_1, "hex"));

let r_compress_2;
if (r_BN_2.isOdd()) {
  r_compress_2 = "03" + signature_2.r.slice(0, 64);
} else {
  r_compress_2 = "02" + signature_2.r.slice(0, 64);
}
const r_point_2 = curve.curve.decodePoint(Buffer.from(r_compress_2, "hex"));

let r_compress_3;
if (r_BN_2.isOdd()) {
  r_compress_3 = "03" + signature_3.r.slice(0, 64);
} else {
  r_compress_3 = "02" + signature_3.r.slice(0, 64);
}
const r_point_3 = curve.curve.decodePoint(Buffer.from(r_compress_3, "hex"));

const r_sum_test = r_point_1.add(r_point_2).add(r_point_3);
const r_sum_output = toHexString(r_sum_test.encode()).slice(2);

const signatureSum = { r: r_sum_output, s: s_sum_output };

// ------- Check Sum Signature in App --------
console.log(signatureSum);
const res = verify(msgHash, signatureSum, pubKeySumHexString);
console.log(res);
