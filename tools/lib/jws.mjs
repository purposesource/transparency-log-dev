// Compact ES256 JWS, checked with node:crypto alone.
//
// A checkpoint token is `base64url(header) . base64url(payload) . base64url(r || s)`: header
// {alg: ES256, kid, typ: application/psn-ct-checkpoint+jws}, payload the ct-checkpoint.v1
// object in RFC 8785 form (ct-checkpoint.v1 x-psn.signature), signature the raw 64-byte
// concatenation of two P-256 scalars (RFC 7518 §3.4).

import { createPublicKey, verify } from 'node:crypto';

import { jcs } from './canonical.mjs';
import { parseJson } from './schema.mjs';

/** Unpadded base64url bytes, refusing any second spelling of the same bytes. */
export function base64urlBytes(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]+$/.test(segment) || segment.length % 4 === 1) return null;
  const bytes = Buffer.from(segment, 'base64url');
  return bytes.toString('base64url') === segment ? bytes : null;
}

/**
 * The parts of a compact JWS, or the reason it is not one. The payload must be its own
 * RFC 8785 text byte for byte: that is what the contract says is signed, and it also refuses
 * a payload naming a member twice.
 */
export function parseCompact(compact) {
  if (typeof compact !== 'string') return { problem: 'the token is not a string' };
  const parts = compact.split('.');
  if (parts.length !== 3) return { problem: 'the token is not three dot-separated parts' };
  const [h, p, s] = parts;
  const headerBytes = base64urlBytes(h);
  const payloadBytes = base64urlBytes(p);
  const signature = base64urlBytes(s);
  if (!headerBytes || !payloadBytes || !signature) return { problem: 'a part of the token is not canonical unpadded base64url' };
  const header = parseJson(headerBytes);
  if (header.problem) return { problem: `the protected header ${header.problem}` };
  const payload = parseJson(payloadBytes);
  if (payload.problem) return { problem: `the payload ${payload.problem}` };
  let canonical;
  try {
    canonical = jcs(payload.value);
  } catch {
    return { problem: 'the payload has no RFC 8785 form (a non-integer number)' };
  }
  if (canonical !== payloadBytes.toString('utf8')) return { problem: 'the payload is not in RFC 8785 (JCS) form, which is what ct-checkpoint.v1 says is signed' };
  return {
    header: header.value,
    payload: payload.value,
    signature,
    signingInput: Buffer.from(`${h}.${p}`, 'ascii'),
  };
}

/** True when `signature` is a valid ES256 signature of `signingInput` by the P-256 public key `jwk`. */
export function verifyEs256(signingInput, signature, jwk) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  let key;
  try {
    key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
  } catch {
    return false;
  }
  return verify('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature);
}
