/**
 * Server-side API client.
 *
 * All requests are made from the Next.js server (RSC / route handlers) — never
 * from the browser — so the API stays on a private network and the tenant identity
 * is attached by trusted server code rather than by client-supplied headers.
 */

const API_URL = process.env.API_URL ?? 'http://localhost:4000';

/**
 * AUTH SEAM: in production this is the organisation resolved from the NextAuth
 * session. The demo fallback keeps local development unauthenticated but explicit.
 */
export const DEMO_ORGANIZATION_ID = process.env.DEMO_ORGANIZATION_ID ?? 'org_demo';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface ApiFetchOptions {
  organizationId?: string;
  userId?: string;
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  /** Next.js cache directive. Scan data is always live, so the default is no-store. */
  cache?: RequestCache;
  signal?: AbortSignal;
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    method: options.method ?? 'GET',
    cache: options.cache ?? 'no-store',
    headers: {
      'content-type': 'application/json',
      'x-organization-id': options.organizationId ?? DEMO_ORGANIZATION_ID,
      ...(options.userId ? { 'x-user-id': options.userId } : {}),
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    ...(options.signal ? { signal: options.signal } : {}),
  });

  const text = await response.text();
  const payload: unknown = text.length > 0 ? safeJson(text) : undefined;

  if (!response.ok) {
    const shaped = payload as { error?: { code?: string; message?: string } } | undefined;
    throw new ApiError(
      response.status,
      shaped?.error?.code ?? 'REQUEST_FAILED',
      shaped?.error?.message ?? `Request to ${path} failed with ${response.status}.`,
    );
  }

  return payload as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
