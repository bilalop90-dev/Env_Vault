/* ENV Vault Checker — client-side scanner engine.
 *
 * Architectural rule: nothing in here ever sends .env content to a server.
 * The only network call is fetching the ruleset from /api/rules. All parsing,
 * matching, and masking happens locally in the browser.
 */

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const API_BASE_URL = 'http://localhost:8080'; // Will be updated to Render URL in Phase 6
const RULES_CACHE_KEY = 'envvault_rules_cache';
const RULES_CACHE_TTL = 86400000; // 24 hours in ms

// Severity ordering, used to keep the single highest-risk match per variable.
const SEVERITY_RANK = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };

// ─── RULESET FETCHER (with cache) ────────────────────────────────────────────
/**
 * Returns the detection ruleset, preferring a fresh localStorage cache.
 *
 * Behaviour:
 *  - fresh cache (within TTL) → return cached rules, no network call
 *  - stale/missing cache → fetch from the API and refresh the cache
 *  - fetch fails but a (stale) cache exists → fall back to the stale cache
 *  - fetch fails and no cache at all → throw a descriptive error
 */
async function getRules() {
  let cached = null;
  try {
    const raw = localStorage.getItem(RULES_CACHE_KEY);
    if (raw) cached = JSON.parse(raw);
  } catch (_) {
    cached = null; // corrupt cache — ignore and refetch
  }

  const hasCachedRules = cached && Array.isArray(cached.rules);
  const isFresh =
    hasCachedRules &&
    typeof cached.cachedAt === 'number' &&
    Date.now() - cached.cachedAt < RULES_CACHE_TTL;

  if (isFresh) return cached.rules;

  try {
    const response = await fetch(`${API_BASE_URL}/api/rules`);
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    const rules = await response.json();

    try {
      localStorage.setItem(
        RULES_CACHE_KEY,
        JSON.stringify({ rules, cachedAt: Date.now() })
      );
    } catch (_) {
      // localStorage may be full or unavailable — caching is best-effort.
    }

    return rules;
  } catch (err) {
    if (hasCachedRules) return cached.rules; // stale is better than nothing
    throw new Error(
      'Could not load detection rules. Please check your connection and try again.'
    );
  }
}

// ─── .env PARSER ─────────────────────────────────────────────────────────────
/**
 * Parses raw .env text into an array of { key, value, line } objects.
 * Pure function, no side effects.
 *
 * Rules:
 *  - split on newline; trim each line
 *  - skip blank lines and comment lines (starting with '#')
 *  - skip lines with no '=' (they map to null and are dropped)
 *  - split on the FIRST '=' only, so values may contain '=' signs
 *  - trim both key and value; an empty value (KEY=) is kept as ''
 *
 * @param {string} rawText
 * @returns {{key: string, value: string, line: number}[]}
 */
function parseEnvFile(rawText) {
  const lines = String(rawText).split('\n');
  const variables = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1; // 1-indexed
    const trimmed = lines[i].trim();

    if (trimmed === '') continue;          // blank line
    if (trimmed.startsWith('#')) continue; // comment

    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;               // not a KEY=VALUE line → null → skip

    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();

    if (key === '') continue;              // '=value' with no key is meaningless

    variables.push({ key, value, line: lineNumber });
  }

  return variables;
}

// ─── VALUE MASKER ────────────────────────────────────────────────────────────
/**
 * Masks a secret value for display. Never returns the full value.
 *  - empty or shorter than 4 chars → '****'
 *  - otherwise → first 4 characters + '****'
 *
 * @param {string} value
 * @returns {string}
 */
function maskValue(value) {
  if (!value || value.length < 4) return '****';
  return value.slice(0, 4) + '****';
}

// ─── CORE SCANNER ────────────────────────────────────────────────────────────
/**
 * Scans raw .env text and classifies every variable by risk.
 *
 * Each rule's pattern is tested (case-insensitively) against both the variable's
 * value and the reconstructed `KEY=VALUE` line. Testing the line as well lets
 * key-name-driven rules (e.g. jwt-secret, generic-high-entropy) match on the key,
 * while value-only rules still match within the line. A variable is reported once,
 * using its highest-severity match.
 *
 * @param {string} rawText
 * @returns {Promise<{critical:Array, high:Array, medium:Array, safe:Array, totalScanned:number}>}
 */
async function scanEnv(rawText) {
  const variables = parseEnvFile(rawText);
  const rules = await getRules();

  const results = {
    critical: [],
    high: [],
    medium: [],
    safe: [],
    totalScanned: variables.length,
  };

  for (const variable of variables) {
    const candidateLine = `${variable.key}=${variable.value}`;
    let bestRule = null;

    for (const rule of rules) {
      let regex;
      try {
        regex = new RegExp(rule.pattern, 'i');
      } catch (_) {
        continue; // skip a malformed pattern rather than break the whole scan
      }

      const matched = regex.test(variable.value) || regex.test(candidateLine);
      if (!matched) continue;

      if (
        !bestRule ||
        (SEVERITY_RANK[rule.riskLevel] || 0) > (SEVERITY_RANK[bestRule.riskLevel] || 0)
      ) {
        bestRule = rule;
      }
    }

    if (bestRule) {
      const entry = {
        key: variable.key,
        maskedValue: maskValue(variable.value),
        riskLevel: bestRule.riskLevel,
        matchedRule: {
          id: bestRule.id,
          name: bestRule.name,
          description: bestRule.description,
          remediation: bestRule.remediation,
          pattern: bestRule.pattern,
        },
        line: variable.line,
      };

      if (bestRule.riskLevel === 'CRITICAL') results.critical.push(entry);
      else if (bestRule.riskLevel === 'HIGH') results.high.push(entry);
      else if (bestRule.riskLevel === 'MEDIUM') results.medium.push(entry);
    } else {
      // Safe variables are not secrets, so their values are NOT masked.
      results.safe.push({ key: variable.key, value: variable.value, line: variable.line });
    }
  }

  return results;
}

// ─── DEV ONLY — console test hook ────────────────────────────────────────────
// Paste an .env string into __envVaultTest(`...`) in the browser console to
// inspect classification. Removed/disabled once the UI is wired in Phase 4.
window.__envVaultTest = async (sampleText) => {
  const result = await scanEnv(sampleText);
  console.table(result.critical);
  console.table(result.high);
  console.table(result.safe);
  return result;
};
