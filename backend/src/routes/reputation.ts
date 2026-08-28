import { Router, Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { CertificateService } from '../services/CertificateService';
import { queryTimescale } from '../db/timescale';
import { readCache, reputationKey, writeCache } from '../indexer/cache';
import { buildReputationVC } from '../lib/vc';

const router = Router();

const DEFAULT_HISTORY_DAYS = 30;
const MAX_HISTORY_DAYS = 365;

// Zod schema for validating the export certificate request
const exportCertificateSchema = z.object({
  did: z.string().min(1, "DID is required"),
  trustScore: z.number().min(0).max(100, "Trust score must be between 0 and 100")
});

const validateExportRequest = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const validatedData = exportCertificateSchema.parse(req.body);
    req.body = validatedData;
    next();
  } catch (error) {
    if (error instanceof ZodError) {
      const formattedErrors = error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
      }));

      res.status(400).json({
        error: 'Bad Request',
        details: formattedErrors,
      });
      return;
    }
    next(error);
  }
};

// POST /export/certificate - Exports a Reputation Certificate (VC)
router.post('/export/certificate', validateExportRequest, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { did, trustScore } = req.body;

    // Generate the Verifiable Credential using our KMS-backed service
    const token = await CertificateService.generateReputationCertificate(did, trustScore);

    res.status(200).json({
      message: 'Certificate generated successfully',
      certificate: token
    });
  } catch (error) {
    console.error('Error generating certificate:', error);
    res.status(500).json({
      error: 'Internal Server Error'
    });
  }
});

export interface ReputationSnapshot {
  date: string;
  fulfilled: number;
  late: number;
  breached: number;
}

// GET /:address/history - Daily reputation snapshots for an address
router.get('/:address/history', async (req: Request, res: Response) => {
  const { address } = req.params;
  const requested = parseInt(String(req.query.days ?? DEFAULT_HISTORY_DAYS), 10);
  const days = Number.isNaN(requested)
    ? DEFAULT_HISTORY_DAYS
    : Math.min(Math.max(requested, 1), MAX_HISTORY_DAYS);

  try {
    // Snapshots are only written on days an address was active, so each day in
    // the window carries the most recent snapshot at or before it forward.
    const result = await queryTimescale(
      `SELECT
         to_char(series.day, 'YYYY-MM-DD') AS date,
         COALESCE(snapshot.fulfilled, 0) AS fulfilled,
         COALESCE(snapshot.late, 0) AS late,
         COALESCE(snapshot.breached, 0) AS breached
       FROM generate_series(
              (CURRENT_DATE - ($2::int - 1))::timestamp,
              CURRENT_DATE::timestamp,
              INTERVAL '1 day'
            ) AS series(day)
       LEFT JOIN LATERAL (
         SELECT fulfilled, late, breached
         FROM reputation_snapshots
         WHERE address = $1
           AND day <= series.day::date
         ORDER BY day DESC
         LIMIT 1
       ) snapshot ON TRUE
       ORDER BY series.day`,
      [address, days],
    );

    const history: ReputationSnapshot[] = result.rows.map((row) => ({
      date: row.date,
      fulfilled: Number(row.fulfilled),
      late: Number(row.late),
      breached: Number(row.breached),
    }));

    res.json(history);
  } catch (error) {
    console.error('Error fetching reputation history:', error);
    res.status(500).json({ error: 'Failed to fetch reputation history' });
  }
});

export interface Reputation {
  address: string;
  trustScore: number | null;
  fulfilled: number;
  late: number;
  breached: number;
  total: number;
}

const STELLAR_ADDRESS = /^[GC][A-Z2-7]{55}$/;

// Scoped to party_a, the issuer. This mirrors the contract, where Reputation
// only counts an address's record as the party who made the commitment.
const loadReputation = async (address: string): Promise<Reputation> => {
  const result = await queryTimescale(
    `SELECT
       COUNT(*) FILTER (WHERE outcome = 'fulfilled') AS fulfilled,
       COUNT(*) FILTER (WHERE outcome = 'late') AS late,
       COUNT(*) FILTER (WHERE outcome = 'breached') AS breached,
       COUNT(*) AS total,
       (SELECT trust_score FROM trust_score_snapshots
         WHERE address = $1 ORDER BY time DESC LIMIT 1) AS trust_score
     FROM commitment_outcomes
     WHERE party_a = $1`,
    [address],
  );

  const row = result.rows[0];
  return {
    address,
    trustScore: row.trust_score === null ? null : Number(row.trust_score),
    fulfilled: Number(row.fulfilled),
    late: Number(row.late),
    breached: Number(row.breached),
    total: Number(row.total),
  };
};

// GET /:address/vc - Returns a signed W3C Verifiable Credential for the address
router.get('/:address/vc', async (req: Request, res: Response) => {
  const { address } = req.params;

  if (typeof address !== 'string' || !STELLAR_ADDRESS.test(address)) {
    res.status(400).json({ error: 'Invalid Stellar address' });
    return;
  }

  try {
    const stats = await loadReputation(address);
    const vc = await buildReputationVC(stats);
    res
      .set('Content-Type', 'application/ld+json')
      .status(200)
      .json(vc);
  } catch (error) {
    console.error('Error generating Verifiable Credential:', error);
    res.status(500).json({ error: 'Failed to generate Verifiable Credential' });
  }
});

// GET /:address - Aggregate compliance history, served from Redis when available
router.get('/:address', async (req: Request, res: Response) => {
  const { address } = req.params;

  if (typeof address !== 'string' || !STELLAR_ADDRESS.test(address)) {
    res.status(400).json({ error: 'Invalid Stellar address' });
    return;
  }

  const key = reputationKey(address);

  const cached = await readCache<Reputation>(key);
  if (cached) {
    res.set('X-Cache', 'HIT').json(cached);
    return;
  }

  try {
    const reputation = await loadReputation(address);
    await writeCache(key, reputation);
    res.set('X-Cache', 'MISS').json(reputation);
  } catch (error) {
    console.error('Error fetching reputation:', error);
    res.status(500).json({ error: 'Failed to fetch reputation' });
  }
});

export default router;
