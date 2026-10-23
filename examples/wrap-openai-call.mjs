/**
 * Wrap a model call with a guard session — no API key needed to run this demo;
 * the "model" is a stub. Watch the placeholder round-trip:
 *
 *   node examples/wrap-openai-call.mjs
 */
import { createGuardSession } from "../dist/esm/index.js";

const guard = createGuardSession();

const userMessage = [
  "Summarize this support ticket for our CRM:",
  "Customer jane.doe@acme.io (call back on +1 (555) 019-8877) says the deploy failed.",
  "Our DATABASE_URL is postgres://svc_app:S3cret@db-prod.internal:5432/shop",
  "and I pasted my OpenAI key sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa here by mistake.",
].join("\n");

const outgoing = guard.redactDeep({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: userMessage }],
});

console.log("=== what the provider receives ===");
console.log(outgoing.messages[0].content);

// Pretend this is the model's reply, referencing the placeholder.
const modelReply = "Summary: outage on deploy for [EMAIL_1]; callback requested via [PHONE_1]. Advise rotating the credentials that appeared in the ticket.";

console.log("\n=== what your app sees after restore ===");
console.log(guard.restore(modelReply));
