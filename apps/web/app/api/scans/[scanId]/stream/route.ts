import type { NextRequest } from 'next/server';

/**
 * Server-Sent Events proxy for live scan progress.
 *
 * Implemented as a polling proxy rather than a direct Redis subscription so the
 * browser never needs a path to Redis. At scale this is replaced by subscribing to
 * the `syscanner:scan-progress:<scanId>` pub/sub channel and forwarding each
 * message, which removes the polling latency; the wire format below is unchanged.
 */
export const dynamic = 'force-dynamic';

const API_URL = process.env.API_URL ?? 'http://localhost:4000';
const POLL_INTERVAL_MS = 2_000;
/** Cap the stream so a forgotten browser tab cannot poll forever. */
const MAX_DURATION_MS = 10 * 60 * 1_000;

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ scanId: string }> },
): Promise<Response> {
  const { scanId } = await context.params;
  const organizationId = request.headers.get('x-organization-id') ?? 'org_demo';
  const encoder = new TextEncoder();
  const startedAt = Date.now();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: string, data: unknown): void => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };

      let lastStatus: string | undefined;

      const poll = async (): Promise<boolean> => {
        try {
          const response = await fetch(`${API_URL}/v1/scans/${scanId}`, {
            headers: { 'x-organization-id': organizationId },
            cache: 'no-store',
          });

          if (!response.ok) {
            send('error', { code: 'SCAN_UNAVAILABLE', status: response.status });
            return true;
          }

          const scan = (await response.json()) as { status: string; totalFindings: number };

          // Only emit on change: a status stream that repeats itself every 2s is
          // just noise for the client.
          if (scan.status !== lastStatus) {
            lastStatus = scan.status;
            send('status', { scanId, status: scan.status });
          }

          if (scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'PARTIAL') {
            send('done', { scanId, status: scan.status, totalFindings: scan.totalFindings });
            return true;
          }

          return Date.now() - startedAt > MAX_DURATION_MS;
        } catch {
          send('error', { code: 'UPSTREAM_UNREACHABLE' });
          return true;
        }
      };

      const tick = async (): Promise<void> => {
        const finished = await poll();
        if (finished) {
          controller.close();
          return;
        }
        setTimeout(() => void tick(), POLL_INTERVAL_MS);
      };

      await tick();
    },
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
    },
  });
}
