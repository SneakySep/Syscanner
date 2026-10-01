/**
 * @syscanner/db — the single source of truth for the Syscanner data model.
 *
 * Only this package may depend on `@prisma/client`. Every other package imports
 * the re-exported client and generated types from here, so a schema change is a
 * one-line change and a `pnpm db:generate`.
 */
export * from '@prisma/client';
export { prisma, createPrismaClient } from './client';
