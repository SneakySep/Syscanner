import type { FastifyRequest } from 'fastify';

/**
 * Tenant resolution.
 *
 * The API gateway authenticates the caller (JWT/JWKS) and forwards the resolved
 * organisation as a header. The API re-derives nothing from the request body, so a
 * client cannot claim to be another tenant.
 *
 * In production this header is only trusted because the gateway strips any
 * client-supplied copy of it; that is enforced by an infrastructure test.
 */
export const TENANT_HEADER = 'x-organization-id';

export interface TenantContext {
  organizationId: string;
  /** Set when the caller authenticated with a user session rather than an API token. */
  userId?: string;
}

export class TenantResolutionError extends Error {
  public readonly statusCode = 401;
  public readonly code = 'TENANT_REQUIRED';

  constructor() {
    super(`Missing ${TENANT_HEADER} header; the request was not authenticated.`);
    this.name = 'TenantResolutionError';
  }
}

export function requireTenant(request: FastifyRequest): TenantContext {
  const header = request.headers[TENANT_HEADER];
  const organizationId = Array.isArray(header) ? header[0] : header;

  if (!organizationId || organizationId.trim().length === 0) {
    throw new TenantResolutionError();
  }

  const userIdHeader = request.headers['x-user-id'];
  const userId = Array.isArray(userIdHeader) ? userIdHeader[0] : userIdHeader;

  return { organizationId: organizationId.trim().slice(0, 64), userId };
}
