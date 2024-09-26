import { secp256k1 } from "@noble/curves/secp256k1";
import { sha3_256 } from "@noble/hashes/sha3";
import {
  AlmostForeignField,
  Bool,
  Bytes,
  createEcdsaV2,
  createForeignCurveV2,
  Hash,
  Crypto as O1Crypto,
} from "o1js";
const PAYLOAD = new Uint8Array([1]);

class Curve extends createForeignCurveV2(O1Crypto.CurveParams.Secp256k1) {}
class Ecdsa extends createEcdsaV2(Curve) {}

function prepare() {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv);
  const hash = sha3_256(PAYLOAD);
  // console.log("noble hash", Buffer.from(hash).toString("hex"));
  const sig = secp256k1.sign(hash, priv);

  // const isValid = secp256k1.verify(sig, hash, pub) === true;
  // console.log("noble/secp256k1 can validate itself:", isValid);

  const uncompressedPub =
    secp256k1.ProjectivePoint.fromHex(pub).toRawBytes(false);
  const xArr = uncompressedPub.slice(1, 33);
  const yArr = uncompressedPub.slice(33);

  const x = BigInt("0x" + Buffer.from(xArr).toString("hex"));
  const y = BigInt("0x" + Buffer.from(yArr).toString("hex"));

  const r = BigInt("0x" + sig.r.toString(16));
  const s = BigInt("0x" + sig.s.toString(16));

  return {
    x,
    y,
    r,
    s,
  };
}

function main() {
  const { x, y, r, s } = prepare();

  const pubKey = new Curve({
    x,
    y,
  });

  const sign = new Ecdsa({
    r,
    s,
  });

  const o1bytes = Bytes.from(PAYLOAD);
  const o1hash = Hash.SHA3_256.hash(o1bytes);
  // console.log("o1js hash", o1hash.toHex());

  // Succeeds but not a provable transformation here
  const hashBigInt = BigInt("0x" + o1hash.toHex());
  let o1IsValidV2 = sign.verifySignedHashV2(hashBigInt, pubKey);
  console.log("verifySignedHashV2 bigint:", o1IsValidV2.toBoolean());

  // No built in function to turn Bytes into AlmostForeignField
  const fields = o1hash.toFields();
  const bits: Bool[] = [];
  for (let i = 0; i < 32; i++) {
    for (const bit of fields[i].toBits()) {
      bits.push(bit);
    }
  }
  // I need to somehow instantiate this type?
  // const ff = AlmostForeignField.fromBits(bits);
  // o1IsValidV2 = sign.verifySignedHashV2(ff, pubKey);
  // console.log("verifySignedHashV2 Bool[]:", o1IsValidV2.toBoolean());
}

main();
