var EC = require("elliptic").ec;
const curve = new EC("secp256k1");
const BN = require("bn.js");
const sha256 = require("js-sha256");
const secp256k1 = require("bcrypto/lib/secp256k1");
const schnorr = require("bip-schnorr");
const math = schnorr.math;

// ------ utils -------
const POOL64 = Buffer.allocUnsafe(64);

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

/*
// ------ generate random key -------
// With a compressed point, we get a 32 byte compressed value (64 hex characters), and then add a 02 or a 03 to represent when y is even (02) or odd (03)
const key = secp256k1.privateKeyGenerate();
const pub = secp256k1.publicKeyCreate(key, true);
*/

/*
---- Algorithm ----
---- Signing in Card ----
p: prime order
n: group order
prk: privateKey
pbk = privateKey.multiply(prk)
M: message
k: random
r = curve.g.multiply(k)
e = H(M)
s = (k + prk*e) mod curve.n
Return (e, s)
*/

// ----------- Private Key & Public Key Generation in Individual Card ------------
const privateKey = Buffer.from(
  "dce71358bf6d57dffaf8ac422ea972dca65badd2ce21b585803ea3075b7de388",
  "hex"
);
const privateKey_BN = new BN(privateKey, "hex");
const publicKey = curve.g.mul(privateKey);
const publicKeyHexString = toHexString(publicKey.encode()).slice(2);

// ------- Calculate hash Concatenate Msg in App ---------
const msg = "tuananh";
const msgHash = sha256.digest(Buffer.from(msg, "ascii"));

// ------- Calculate all individual r in Card ---------
const rand_Hex = Array(64)
  .fill()
  .map(() => Math.round(Math.random() * 0xf).toString(16))
  .join("");

let rand_BN = new BN(rand_Hex, "hex");
console.log(rand_Hex);
if (rand_BN.gte(curve.n)) {
  throw new Error("Invalid random number");
}
const r = curve.g.mul(rand_BN);
const r_output = toHexString(r.encode()).slice(2);

// console.log("Original Public Key", toHexString(publicKey.encode()).slice(2)); // toHexString(publicKey.encode()): 04 + PublicKey_x + PublicKey_y
// console.log("Original Public Key x axis only", publicKey.getX().toString(16)); // PublicKey_x

// ------- Calculate all individual s in Card ---------
const hashConcat = new BN(Buffer.from(msgHash, "hex"));
let s = rand_BN.add(hashConcat.mul(privateKey_BN)); // (k + prk*e) mod n
s = s.umod(curve.n);
const s_output = s.toString(16);
const signature = { r: r_output, s: s_output };
console.log(signature);

// ------- Check Signature in App --------
function verify(msgHash, signature, publicKeyString) {
  const r_temp = new BN(signature.r.slice(0, 64), "hex");
  const s_temp = new BN(signature.s, "hex");

  const h = new BN(Buffer.from(msgHash, "hex"));

  if (h.gte(curve.n)) throw new Error("Invalid hashConcatMsg.");
  if (h.isZero()) throw new Error("Invalid hashConcatMsg.");
  if (s_temp.gte(curve.n)) throw new Error("Invalid S value.");

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
  const verify_2 = l.add(r_point);

  //   if (r_verify_2.y.isOdd()) throw new Error("Odd R value.");

  if (verify_1.getX().toString(16) == verify_2.getX().toString(16)) {
    return true;
  } else {
    return false;
  }
}

const res = verify(msgHash, signature, publicKeyHexString);
console.log(res);
