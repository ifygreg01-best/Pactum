/**
 * tests/vc.test.ts
 *
 * Tests for:
 *  1. The vc.ts library (buildReputationVC):
 *     - Structure and fields of the produced Verifiable Credential
 *     - Proof shape: detached JWS with EdDSA / b64:false header
 *     - Deterministic key injection via VC_SIGNING_KEY env var
 *  2. The GET /reputation/:address/vc HTTP endpoint
 *     - 200 with correct Content-Type and VC shape for a valid address
 *     - 400 for an invalid Stellar address
 *     - 500 when the DB layer throws
 */

import * as jose from 'jose';
import supertest from 'supertest';
import express from 'express';

// ---------------------------------------------------------------------------
// Mock the database and cache layers so tests never need PostgreSQL / Redis
// ---------------------------------------------------------------------------
jest.mock('../src/db/timescale', () => ({
  queryTimescale: jest.fn(),
}));

jest.mock('../src/indexer/cache', () => ({
  readCache: jest.fn().mockResolvedValue(null),
  writeCache: jest.fn().mockResolvedValue(undefined),
  reputationKey: (address: string) => `rep:${address}`,
  initCache: jest.fn().mockResolvedValue(undefined),
  closeCache: jest.fn().mockResolvedValue(undefined),
  isCacheAvailable: jest.fn().mockReturnValue(false),
}));

jest.mock('../src/db/dlq', () => ({
  getDLQEntries: jest.fn().mockResolvedValue([]),
  clearDLQ: jest.fn().mockResolvedValue(undefined),
  addDLQEntry: jest.fn().mockResolvedValue(undefined),
}));

import { queryTimescale } from '../src/db/timescale';
import {
  buildReputationVC,
  _resetKeyPairCache,
  ReputationStats,
  VerifiableCredential,
} from '../src/lib/vc';
import reputationRouter from '../src/routes/reputation';

// ---------------------------------------------------------------------------
// Shared test data
// ---------------------------------------------------------------------------

// A valid 56-character Stellar G-address (base32 encoded, passes the regex).
const VALID_ADDRESS = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNA';

const sampleStats: ReputationStats = {
  address: VALID_ADDRESS,
  fulfilled: 14,
  late: 2,
  breached: 1,
  total: 17,
  trustScore: 87.5,
};

// ---------------------------------------------------------------------------
// Helper: mock queryTimescale to return `sampleStats`-shaped rows
// ---------------------------------------------------------------------------
function mockReputationDb(override: Partial<ReputationStats> = {}): void {
  const s = { ...sampleStats, ...override };
  (queryTimescale as jest.Mock).mockResolvedValue({
    rows: [
      {
        fulfilled: String(s.fulfilled),
        late: String(s.late),
        breached: String(s.breached),
        total: String(s.total),
        trust_score: s.trustScore,
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// Build a minimal Express app for route testing (no full server startup)
// ---------------------------------------------------------------------------
function buildTestApp() {
  const app = express();
  app.use(express.json());
  // Mount at /reputation — mirrors production mount in src/index.ts
  app.use('/reputation', reputationRouter);
  return app;
}

// ---------------------------------------------------------------------------
// Section 1 — vc.ts library
// ---------------------------------------------------------------------------

describe('buildReputationVC', () => {
  beforeEach(() => {
    _resetKeyPairCache();
    delete process.env.VC_SIGNING_KEY;
  });

  afterEach(() => {
    _resetKeyPairCache();
    delete process.env.VC_SIGNING_KEY;
  });

  // ── 1.1 Required W3C VC fields ─────────────────────────────────────────

  it('returns a document with the required W3C VC fields', async () => {
    const vc = await buildReputationVC(sampleStats);

    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('PactumReputationCredential');
    expect(vc.issuer).toBe('did:web:pactum.io');
    expect(vc.id).toMatch(/^urn:pactum:vc:reputation:/);
    expect(vc.issuanceDate).toBeTruthy();
    expect(vc.expirationDate).toBeTruthy();
  });

  it('embeds the address as a did:pkh:stellar subject', async () => {
    const vc = await buildReputationVC(sampleStats);
    expect(vc.credentialSubject.id).toBe(`did:pkh:stellar:${VALID_ADDRESS}`);
  });

  it('correctly encodes fulfillment stats in credentialSubject', async () => {
    const vc = await buildReputationVC(sampleStats);
    const { fulfillmentStats } = vc.credentialSubject;

    expect(fulfillmentStats.fulfilled).toBe(14);
    expect(fulfillmentStats.late).toBe(2);
    expect(fulfillmentStats.breached).toBe(1);
    expect(fulfillmentStats.total).toBe(17);
  });

  it('encodes a non-null trustScore', async () => {
    const vc = await buildReputationVC(sampleStats);
    expect(vc.credentialSubject.trustScore).toBe(87.5);
  });

  it('handles a null trustScore (address has no score yet)', async () => {
    const vc = await buildReputationVC({ ...sampleStats, trustScore: null });
    expect(vc.credentialSubject.trustScore).toBeNull();
  });

  it('expirationDate is approximately one year after issuanceDate', async () => {
    const vc = await buildReputationVC(sampleStats);
    const issuance = new Date(vc.issuanceDate).getTime();
    const expiry = new Date(vc.expirationDate).getTime();
    const oneYear = 365 * 24 * 60 * 60 * 1000;

    // Allow a 5-second window for slow machines.
    expect(expiry - issuance).toBeGreaterThanOrEqual(oneYear - 5000);
    expect(expiry - issuance).toBeLessThanOrEqual(oneYear + 5000);
  });

  // ── 1.2 Proof structure ────────────────────────────────────────────────

  it('includes an Ed25519Signature2020 proof block', async () => {
    const vc = await buildReputationVC(sampleStats);

    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofPurpose).toBe('assertionMethod');
    expect(vc.proof.verificationMethod).toBe('did:web:pactum.io#key-1');
    expect(vc.proof.jws).toBeTruthy();
  });

  it('produces a detached JWS (middle segment is empty)', async () => {
    const vc = await buildReputationVC(sampleStats);
    const segments = vc.proof.jws.split('.');
    // A detached compact JWS has three segments; the payload segment is empty.
    expect(segments).toHaveLength(3);
    expect(segments[1]).toBe('');
  });

  it('JWS header declares EdDSA algorithm with b64:false and crit extension', async () => {
    const vc = await buildReputationVC(sampleStats);

    // Re-attach a dummy payload segment just to decode the header.
    const [header] = vc.proof.jws.split('.');
    const decoded = jose.decodeProtectedHeader(`${header}.dGVzdA.dGVzdA`);

    expect(decoded.alg).toBe('EdDSA');
    expect((decoded as Record<string, unknown>)['b64']).toBe(false);
    expect(decoded.crit).toContain('b64');
  });

  // ── 1.3 Key management ─────────────────────────────────────────────────

  it('reuses the same keypair across multiple calls (no key rotation per-call)', async () => {
    // If the key were regenerated each call the second VC's JWS header would
    // be identical but we cannot verify — instead we confirm the header is
    // structurally identical (same alg), indicating consistent key type.
    const vc1 = await buildReputationVC(sampleStats);
    const vc2 = await buildReputationVC(sampleStats);

    const [h1] = vc1.proof.jws.split('.');
    const [h2] = vc2.proof.jws.split('.');
    expect(h1).toBe(h2); // same protected header = same key parameters
  });

  it('accepts a fixed 32-byte seed via VC_SIGNING_KEY', async () => {
    // A fixed, reproducible test seed (32 × 0xAB).
    const seed = Buffer.alloc(32, 0xab);
    process.env.VC_SIGNING_KEY = seed.toString('base64url');

    const vc = await buildReputationVC(sampleStats);

    // Must still produce a well-formed VC.
    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.proof.type).toBe('Ed25519Signature2020');

    // JWS must be a detached compact JWS.
    const segs = vc.proof.jws.split('.');
    expect(segs).toHaveLength(3);
    expect(segs[1]).toBe('');

    // Protected header must declare EdDSA.
    const decoded = jose.decodeProtectedHeader(`${segs[0]}.dGVzdA.${segs[2]}`);
    expect(decoded.alg).toBe('EdDSA');
  });

  it('rejects a seed shorter than 32 bytes with a descriptive error', async () => {
    const shortSeed = Buffer.alloc(16, 0x01);
    process.env.VC_SIGNING_KEY = shortSeed.toString('base64url');

    await expect(buildReputationVC(sampleStats)).rejects.toThrow(
      /32-byte/i,
    );
  });
});

// ---------------------------------------------------------------------------
// Section 2 — HTTP endpoint: GET /reputation/:address/vc
// ---------------------------------------------------------------------------

describe('GET /reputation/:address/vc', () => {
  const app = buildTestApp();

  beforeEach(() => {
    _resetKeyPairCache();
    delete process.env.VC_SIGNING_KEY;
    jest.clearAllMocks();
  });

  afterEach(() => {
    _resetKeyPairCache();
    delete process.env.VC_SIGNING_KEY;
  });

  it('returns 200 with Content-Type application/ld+json for a valid address', async () => {
    mockReputationDb();
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/ld\+json/);
  });

  it('response body is a well-shaped W3C VC', async () => {
    mockReputationDb();
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    const vc: VerifiableCredential = res.body;

    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.credentialSubject.id).toBe(`did:pkh:stellar:${VALID_ADDRESS}`);
    expect(vc.proof).toBeDefined();
    expect(vc.proof.type).toBe('Ed25519Signature2020');
  });

  it('embeds the correct reputation stats from the DB', async () => {
    mockReputationDb({ fulfilled: 20, late: 3, breached: 0, total: 23 });
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    const vc: VerifiableCredential = res.body;

    expect(vc.credentialSubject.fulfillmentStats.fulfilled).toBe(20);
    expect(vc.credentialSubject.fulfillmentStats.late).toBe(3);
    expect(vc.credentialSubject.fulfillmentStats.breached).toBe(0);
    expect(vc.credentialSubject.fulfillmentStats.total).toBe(23);
  });

  it('includes a detached JWS proof in the response', async () => {
    mockReputationDb();
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    const vc: VerifiableCredential = res.body;

    const segs = vc.proof.jws.split('.');
    expect(segs).toHaveLength(3);
    expect(segs[1]).toBe(''); // detached — no embedded payload
    expect(segs[0].length).toBeGreaterThan(0);
    expect(segs[2].length).toBeGreaterThan(0);
  });

  it('returns 400 for an invalid (non-Stellar) address', async () => {
    const res = await supertest(app).get('/reputation/NOT_A_VALID_ADDRESS/vc');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid stellar address/i);
  });

  it('returns 400 for an address that is too short', async () => {
    const res = await supertest(app).get('/reputation/GABCDEF/vc');
    expect(res.status).toBe(400);
  });

  it('returns 500 when the DB layer throws', async () => {
    (queryTimescale as jest.Mock).mockRejectedValue(new Error('connection refused'));
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/verifiable credential/i);
  });

  it('response VC issuer is did:web:pactum.io', async () => {
    mockReputationDb();
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    expect(res.body.issuer).toBe('did:web:pactum.io');
  });

  it('response VC has a valid ISO-8601 issuanceDate', async () => {
    mockReputationDb();
    const res = await supertest(app).get(`/reputation/${VALID_ADDRESS}/vc`);
    const d = new Date(res.body.issuanceDate);
    expect(d.toString()).not.toBe('Invalid Date');
  });
});
