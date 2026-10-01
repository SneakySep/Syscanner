/**
 * @syscanner/core — pure domain logic.
 *
 * Nothing in this package performs I/O, touches the database, or shells out to a
 * scanner. That keeps it trivially testable and safe to import from the control
 * plane, the worker, or the browser.
 */
export * from './fingerprint';
export * from './severity';
export * from './redaction';
export * from './policy';
