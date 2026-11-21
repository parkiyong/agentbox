import { readFileSync } from "node:fs";
import { AgentBoxClient } from "../../sdks/typescript/dist/src/index.js";

/**
 * Example B2B2C Company Backend embedding AgentBox:
 * 1. Registers the company's declarative Blueprint (`agentbox.yaml`)
 * 2. Spawns an autonomous SWE session isolated to `customerId`
 * 3. Mints a short-lived Browser Client Token for `@agentbox/react`
 * 4. Tails canonical SSE events until completion
 */
async function main() {
  const apiBaseUrl = process.env.AGENTBOX_API_URL ?? "http://127.0.0.1:8080";
  const client = new AgentBoxClient({
    apiBaseUrl,
    apiKey: process.env.AGENTBOX_API_KEY ?? "abx_dev_local",
  });

  const blueprintYaml = readFileSync(new URL("./agentbox.yaml", import.meta.url), "utf8");
  const bp = await client.blueprints.put("acme-autofix-swe", blueprintYaml);
  console.log("Registered Blueprint hash:", bp.hash);

  const session = await client.sessions.create({
    customerId: "cust_acme_8842",
    blueprint: "acme-autofix-swe",
    task: "Investigate and fix issue #412 with minimal changes and tests.",
  });
  console.log("Created Session:", session.id);

  // Mint a short-lived, session-scoped JWT for the end-customer's browser UI.
  const clientToken = await client.sessions.createClientToken(session.id, {
    scopes: ["read", "steer", "approve"],
    ttlSeconds: 3600,
  });
  console.log("Minted Browser Client Token (pass to <AgentBoxProvider>):", clientToken.token.slice(0, 32) + "...");

  for await (const evt of client.sessions.events(session.id)) {
    console.log(`[#${evt.seq}] ${evt.type}`, evt.payload);
  }

  const diff = await client.sessions.getDiff(session.id);
  console.log("Final diff stats:", diff.stats);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
