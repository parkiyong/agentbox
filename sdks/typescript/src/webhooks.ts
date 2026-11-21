import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Verifies the `X-AgentBox-Signature` header (`sha256=<hex>`) using timing-safe comparison.
 */
export function verifyWebhookSignature(
  secret: string,
  rawBody: string | Uint8Array,
  signatureHeader: string,
): boolean {
  if (!secret || !signatureHeader.startsWith("sha256=")) {
    return false;
  }
  const expected =
    "sha256=" + createHmac("sha256", secret).update(rawBody).digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signatureHeader, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
