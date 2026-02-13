/**
 * Vulcn Session Utilities
 *
 * Types and utilities used by the driver system for HTTP request metadata.
 */

/** HTTP request metadata for Tier 1 fast scanning */
export interface CapturedRequest {
  /** Request method */
  method: string;
  /** Full URL */
  url: string;
  /** Request headers */
  headers: Record<string, string>;
  /** Form data (for POST) */
  body?: string;
  /** Content type */
  contentType?: string;
  /** Which form field is injectable */
  injectableField?: string;
  /** Session name this request belongs to */
  sessionName: string;
}
