// Reviewer glossary. Documentation only — nothing here executes.
export const GLOSSARY = {
  serviceRole: "A service_role key bypasses row level security entirely.",
  weakHash: "Passwords stored with md5 or sha1 are considered broken.",
  randomTokens: "Session tokens built from Math.random are predictable.",
  webhookSignature: "A webhook endpoint must verify the provider's signature.",
  sqlInjection: "Never build SQL by concatenating strings: SELECT * FROM users.",
};
