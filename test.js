var EC = require("elliptic").ec;
const curve = new EC("secp256k1");
const BN = require("bn.js");
const sha256 = require("js-sha256");
const secp256k1 = require("bcrypto/lib/secp256k1");

// ------ utils -------
const POOL64 = Buffer.allocUnsafe(64);

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function hashConcatMsg(msg, r) {
  const R = r.toArrayLike(Buffer, "be", 32);
  const B = POOL64;
  R.copy(B, 0);
  msg.copy(B, 32);
  return new BN(sha256.digest(B));
}

/*
// ------ generate random key -------
// With a compressed point, we get a 32 byte compressed value (64 hex characters), and then add a 02 or a 03 to represent when y is even (02) or odd (03)
const key = secp256k1.privateKeyGenerate();
const pub = secp256k1.publicKeyCreate(key, true);
*/

/*
---- Algorithm ----
---- Signing ----
p: prime order
n: group order
prk: privateKey
pbk = privateKey.multiply(prk)
M: message
k: random
r = curve.g.multiply(k)
e = H(M || r)
s = (k - prk*e) mod n
Return (e, s)
*/

/*
---- verifying ----
r_verify = curve.g.multiply(s).add(pbk.multiply(e))
e_verify = H(M || r_verify)
if(e_verify == e) {
  return true
} else {
  return false
}
*/

const msg = "tuananh";

const msgHash = sha256.digest(Buffer.from(msg, "ascii"));

const privateKey = Buffer.from(
  "dce71358bf6d57dffaf8ac422ea972dca65badd2ce21b585803ea3075b7de388",
  "hex"
);

const privateKey_BN = new BN(privateKey, "hex");
const publicKey = curve.g.mul(privateKey);
const publicKeyHexString = toHexString(publicKey.encode()).slice(2);

const rand_Hex = Array(64)
  .fill()
  .map(() => Math.round(Math.random() * 0xf).toString(16))
  .join("");

let rand_BN = new BN(rand_Hex, "hex");

const r = curve.g.mul(rand_BN);
const r_output = toHexString(r.encode()).slice(2);
if (r.y.isOdd()) {
  rand_BN = rand_BN.umod(curve.n);
  rand_BN = curve.n.sub(rand_BN);
}
// console.log("Original Public Key", toHexString(publicKey.encode()).slice(2)); // toHexString(publicKey.encode()): 04 + PublicKey_x + PublicKey_y
// console.log("Original Public Key x axis only", publicKey.getX().toString(16)); // PublicKey_x
const e = hashConcatMsg(Buffer.from(msgHash, "hex"), r.getX());
let s = rand_BN.sub(e.imul(privateKey_BN)); // (k - prk*e) mod n
s = s.umod(curve.n);
const s_output = s.toString(16);
const signature = { r: r_output, s: s_output };
console.log(signature);

// // ------- verify -------
// const r_temp = new BN(signature.r.slice(0, 64), "hex");
// const e_temp = hashConcatMsg(Buffer.from(msgHash, "hex"), r_temp);
// const l = publicKey.mul(e_temp);
// const s_temp = new BN(signature.s, "hex");
// const r_verify = l.add(curve.g.mul(s_temp));
// if (r_verify.getX().toString(16) == signature.r.slice(0, 64)) {
//   console.log("Verify Signature OK");
// } else {
//   console.log("Verify Signature Fail");
// }

function verify(msgHash, signature, publicKeyString) {
  const r_temp = new BN(signature.r.slice(0, 64), "hex");
  const s_temp = new BN(signature.s, "hex");

  const h = hashConcatMsg(Buffer.from(msgHash, "hex"), r_temp);

  if (h.gte(curve.n)) throw new Error("Invalid hashConcatMsg.");
  if (h.isZero()) throw new Error("Invalid hashConcatMsg.");
  if (s_temp.gte(curve.n)) throw new Error("Invalid S value.");

  // if (r_temp.gt(curve.p)) throw new Error("Invalid R value.");

  const publicKeyBN = new BN(publicKeyString, "hex");

  let pubCompress;
  if (publicKeyBN.isOdd()) {
    pubCompress = "03" + publicKeyString.slice(0, 64);
  } else {
    pubCompress = "02" + publicKeyString.slice(0, 64);
  }

  const k = curve.curve.decodePoint(Buffer.from(pubCompress, "hex"));
  const l = k.mul(h);
  const r = curve.g.mul(signature.s);
  const r_verify = l.add(r);

  if (r_verify.y.isOdd()) throw new Error("Odd R value.");

  if (r_verify.getX().toString(16) == signature.r.slice(0, 64)) {
    return true;
  } else {
    return false;
  }
}

const res = verify(msgHash, signature, publicKeyHexString);
console.log(res);

// ------ recover PublicKey from signature & msg -----------

const r_temp = new BN(signature.r.slice(0, 64), "hex");
const e_temp = hashConcatMsg(Buffer.from(msgHash, "hex"), r_temp);
const s_temp = new BN(signature.s, "hex");

let e_tempInv = e_temp.invm(curve.n);
e_tempInv = e_tempInv.umod(curve.n);
let s_temp_1 = s_temp;
s_temp_1 = curve.n.sub(s_temp_1);
s_temp_1 = s_temp_1.umod(curve.n);
s_temp_1 = s_temp_1.imul(e_tempInv);
s_temp_1 = s_temp_1.umod(curve.n);

const R = curve.curve.pointFromX(signature.r.slice(0, 64), false);
let l_temp = R.mul(e_tempInv);
let r_temp_1 = curve.g.mul(s_temp_1);
const pbk_recover = l_temp.add(r_temp_1);

l_temp = pbk_recover.mul(e_temp);
r_temp_1 = curve.g.mul(s_temp);
const rl = l_temp.add(r_temp_1);

if (rl.y.isOdd()) throw new Error("Odd R value.");
if (!rl.getX().eq(r_temp)) throw new Error("Could not recover pubkey.");

console.log("Recovery Public Key", toHexString(pbk_recover.encode().slice(1)));
