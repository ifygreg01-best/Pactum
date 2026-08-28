/**
 * vc.ts — W3C Verifiable Credential utilities for Pactum reputation exports.
 *
 * Signing algorithm: EdDSA (Ed25519) using the jose library.
 *
 * The signing key is read from the VC_SIGNING_KEY environment variable, which
 * must be a base64url-encoded 32-byte Ed25519 private key seed.  If the
 * variable is absent, a fresh keypair is generated in memory for the lifetime
 * of the current process (useful for development; not suitable for production
 * because the key changes on every restart).
 *
 * Generate a stable key once and store it in .env:
 *   node -e "const {randomBytes}=require('crypto'); console.log(randomBytes(32).toString('base64url'))"
 */

import * as jose from 'jose';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReputationStats {
  address: string;
  fulfilled: number;
  late: number;
  breached: number;
  total: number;
  trustScore: number | null;
}

/** A W3C Verifiable Credential document (JSON-LD representation). */
export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: {
    id: string;
    fulfillmentStats: {
      fulfilled: number;
      late: number;
      breached: number;
      total: number;
    };
    trustScore: number | null;
  };
  proof: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    /** Compact JWS detached signature (RFC 7797). */
    jws: string;
  };
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/** Cached keypair, initialised once per process. */
let cachedKeyPair: { privateKey: jose.KeyLike; publicKey: jose.KeyLike } | null = null;

/**
 * Returns (and lazily initialises) the Ed25519 keypair used for VC signing.
 *
 * Reads VC_SIGNING_KEY from the environment.  The value must be a
 * base64url-encoded 32-byte seed (the raw private key scalar).  When the
 * variable is unset, a fresh ephemeral keypair is generated.
 */
async function getSigningKeyPair(): Promise<{ privateKey: jose.KeyLike; publicKey: jose.KeyLike }> {
  if (cachedKeyPair) {
    return cachedKeyPair;
  }

  const seedEnv = process.env.VC_SIGNING_KEY;

  if (seedEnv) {
    // Import the raw 32-byte seed as a JWK-style Ed25519 private key.
    // jose expects the "d" parameter (base64url private scalar) to be 32 bytes.
    const jwk: jose.JWK = {
      kty: 'OKP',
      crv: 'Ed25519',
      d: seedEnv,
      // x (public key) is derived automatically by jose during importJWK when
      // only "d" is supplied — but jose requires "x" to be present in the JWK.
      // We therefore generate a full keypair from the seed via importPKCS8 /
      // using @noble/ed25519 which is already in the dependency tree.
      x: await derivePublicKeyBase64url(seedEnv),
    };

    const privateKey = (await jose.importJWK(jwk, 'EdDSA')) as jose.KeyLike;

    // Build the public-key-only JWK for storage.
    const pubJwk: jose.JWK = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
    const publicKey = (await jose.importJWK(pubJwk, 'EdDSA')) as jose.KeyLike;

    cachedKeyPair = { privateKey, publicKey };
  } else {
    // Development fallback: ephemeral keypair, regenerated on each restart.
    console.warn(
      '[vc] VC_SIGNING_KEY is not set — using an ephemeral Ed25519 keypair. ' +
        'VCs will not be verifiable across restarts. Set VC_SIGNING_KEY in .env for production.',
    );
    const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    cachedKeyPair = {
      privateKey: privateKey as jose.KeyLike,
      publicKey: publicKey as jose.KeyLike,
    };
  }

  return cachedKeyPair;
}

/**
 * Derives the Ed25519 public key (base64url-encoded) from a raw 32-byte seed
 * (also base64url-encoded).  Uses Node.js's built-in crypto.subtle so there
 * are no ESM/CJS compatibility issues.
 *
 * The seed is wrapped in a minimal PKCS#8 DER envelope:
 *   SEQUENCE {
 *     INTEGER 0                  (version)
 *     SEQUENCE { OID 1.3.101.112 } (Ed25519)
 *     OCTET STRING { OCTET STRING { <seed> } }
 *   }
 */
async function derivePublicKeyBase64url(seedBase64url: string): Promise<string> {
  const seed = Buffer.from(seedBase64url, 'base64url');
  if (seed.length !== 32) {
    throw new Error(
      `VC_SIGNING_KEY must be a base64url-encoded 32-byte Ed25519 seed (got ${seed.length} bytes)`,
    );
  }

  // Minimal PKCS#8 DER prefix for an Ed25519 private key (RFC 8410):
  //   30 2e                     SEQUENCE (46 bytes)
  //   02 01 00                  INTEGER 0
  //   30 05 06 03 2b 65 70      SEQUENCE { OID 1.3.101.112 }
  //   04 22 04 20               OCTET STRING { OCTET STRING { 32 bytes } }
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const pkcs8Der = Buffer.concat([pkcs8Prefix, seed]);

  const importedKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Der,
    { name: 'Ed25519' },
    true, // extractable — needed to export the JWK including "x"
    ['sign'],
  );

  // crypto.subtle.exportKey('jwk', privateKey) for Ed25519 in Node ≥ 22
  // returns a JWK with both "d" (private) and "x" (public) fields.
  const jwk = await crypto.subtle.exportKey('jwk', importedKey);
  if (!jwk.x) {
    throw new Error('Failed to derive Ed25519 public key from seed');
  }
  return jwk.x;
}

// Allow tests to reset the cached keypair (e.g. to inject a fixed test key).
export function _resetKeyPairCache(): void {
  cachedKeyPair = null;
}

// ---------------------------------------------------------------------------
// VC construction
// ---------------------------------------------------------------------------

const ISSUER_DID = 'did:web:pactum.io';
const VC_TTL_SECONDS = 365 * 24 * 60 * 60; // 1 year

/**
 * Builds and signs a W3C Verifiable Credential that attests to an address's
 * Pactum reputation stats.
 *
 * The credential follows the W3C VC Data Model v1.1:
 *   https://www.w3.org/TR/vc-data-model/
 *
 * The proof is an Ed25519Signature2020-style embedded proof whose `jws` field
 * holds a compact detached JWS (RFC 7797) produced by jose.
 */
export async function buildReputationVC(stats: ReputationStats): Promise<VerifiableCredential> {
  const { privateKey } = await getSigningKeyPair();

  const now = new Date();
  const expiry = new Date(now.getTime() + VC_TTL_SECONDS * 1000);

  // Unique, deterministic credential ID (no DB needed).
  const credentialId = `urn:pactum:vc:reputation:${stats.address}:${now.getTime()}`;

  // The subject DID is a did:pkh for Stellar addresses.
  const subjectDid = `did:pkh:stellar:${stats.address}`;

  const credentialSubject = {
    id: subjectDid,
    fulfillmentStats: {
      fulfilled: stats.fulfilled,
      late: stats.late,
      breached: stats.breached,
      total: stats.total,
    },
    trustScore: stats.trustScore,
  };

  // ------------------------------------------------------------------
  // Sign the credential.
  // We sign a canonical JSON serialisation of the unsigned credential
  // document using a detached compact JWS (RFC 7797 §2).
  // ------------------------------------------------------------------
  const unsignedDocument = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: credentialId,
    type: ['VerifiableCredential', 'PactumReputationCredential'],
    issuer: ISSUER_DID,
    issuanceDate: now.toISOString(),
    expirationDate: expiry.toISOString(),
    credentialSubject,
  };

  const payload = Buffer.from(JSON.stringify(unsignedDocument), 'utf8');

  // Produce a detached JWS: the payload is replaced by an empty string in the
  // serialisation but the signature covers the full payload bytes.
  const jws = await new jose.CompactSign(payload)
    .setProtectedHeader({ alg: 'EdDSA', b64: false, crit: ['b64'] })
    .sign(privateKey);

  // RFC 7797 detached encoding: strip the middle segment so the payload is not
  // embedded in the JWS string itself.
  const [headerB64, , signatureB64] = jws.split('.');
  const detachedJws = `${headerB64}..${signatureB64}`;

  return {
    ...unsignedDocument,
    proof: {
      type: 'Ed25519Signature2020',
      created: now.toISOString(),
      verificationMethod: `${ISSUER_DID}#key-1`,
      proofPurpose: 'assertionMethod',
      jws: detachedJws,
    },
  };
}
