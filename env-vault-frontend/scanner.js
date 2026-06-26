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

// ─── DEV ONLY — console test hook (disabled in Phase 4) ──────────────────────
// The UI below fully drives the scanner, so the console hook is no longer needed.
// Kept commented for quick manual debugging during development.
//
// window.__envVaultTest = async (sampleText) => {
//   const result = await scanEnv(sampleText);
//   console.table(result.critical);
//   console.table(result.high);
//   console.table(result.safe);
//   return result;
// };

// ─── ICONS ───────────────────────────────────────────────────────────────────
// Static, inline SVG markup. These strings are constant (never user input), so
// assigning them via innerHTML is safe. All user-derived text is rendered with
// textContent / createElement further down to prevent XSS.
const SVG_OPEN =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">';

const ICONS = {
  moon: SVG_OPEN + '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>',
  sun:
    SVG_OPEN +
    '<circle cx="12" cy="12" r="5"></circle>' +
    '<line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line>' +
    '<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>' +
    '<line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line>' +
    '<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>',
  loader: SVG_OPEN + '<path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>',
  shieldCheck:
    SVG_OPEN +
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>' +
    '<polyline points="9 12 11.5 14.5 16 9.5"></polyline></svg>',
  alertTriangle:
    SVG_OPEN +
    '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>' +
    '<line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
  bulb:
    SVG_OPEN +
    '<path d="M9 18h6"></path><path d="M10 22h4"></path>' +
    '<path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5.76.76 1.23 1.52 1.41 2.5"></path></svg>',
};

// ─── DOM CONTROLLER ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const THEME_KEY = 'envvault_theme';

  const $ = (id) => document.getElementById(id);
  const themeToggle = $('themeToggle');
  const trustBadge = $('trustBadge');
  const trustIcon = $('trustIcon');
  const trustText = $('trustText');
  const envInput = $('envInput');
  const fileUpload = $('fileUpload');
  const clearBtn = $('clearBtn');
  const scanBtn = $('scanBtn');
  const scanBtnLabel = scanBtn.querySelector('.btn-label');
  const resultsSection = $('resultsSection');
  const resultsList = $('resultsList');
  const resultsMeta = $('resultsMeta');
  const safeList = $('safeList');
  const safeCount = $('safeCount');
  const errorBanner = $('errorBanner');
  const errorText = $('errorText');

  // Safety reset: ensure the error banner is hidden on load regardless of
  // initial HTML/CSS state, before any other flow runs.
  hideError();

  // ── Theme ──────────────────────────────────────────────────────────────────
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    // Show the icon for the theme you can switch TO is a common pattern, but the
    // spec asks for moon while dark and sun while light, so reflect current theme.
    themeToggle.innerHTML = theme === 'dark' ? ICONS.moon : ICONS.sun;
  }

  let currentTheme = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(currentTheme);

  themeToggle.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, currentTheme); } catch (_) {}
    applyTheme(currentTheme);
  });

  // ── Trust badge state ────────────────────────────────────────────────────────
  function setTrust(state, message) {
    trustBadge.classList.remove('is-loading', 'is-ready', 'is-error');
    trustIcon.classList.remove('is-spinning');

    if (state === 'loading') {
      trustBadge.classList.add('is-loading');
      trustIcon.innerHTML = ICONS.loader;
      trustIcon.classList.add('is-spinning');
    } else if (state === 'ready') {
      trustBadge.classList.add('is-ready');
      trustIcon.innerHTML = ICONS.shieldCheck;
    } else {
      trustBadge.classList.add('is-error');
      trustIcon.innerHTML = ICONS.alertTriangle;
    }
    trustText.textContent = message;
  }

  // ── Rules prefetch (warms the cache, surfaces zero-trust status) ─────────────
  setTrust('loading', 'Loading detection rules...');
  getRules()
    .then((rules) => {
      setTrust('ready', `${rules.length} rules loaded — your file stays in this browser`);
    })
    .catch(() => {
      setTrust('error', 'Could not load rules — scan may use cached data');
    });

  // ── Error banner ─────────────────────────────────────────────────────────────
  // Note: `.error-banner` is styled `display: flex`, which overrides the `hidden`
  // attribute on its own, so we also toggle the inline display to truly hide it.
  function showError(message) {
    errorText.textContent = message;
    errorBanner.hidden = false;
    errorBanner.style.display = 'flex';
  }
  function hideError() {
    errorBanner.hidden = true;
    errorBanner.style.display = 'none';
    errorText.textContent = '';
  }

  // ── Results visibility ───────────────────────────────────────────────────────
  function hideResults() {
    resultsSection.hidden = true;
  }

  // ── Scanning state ───────────────────────────────────────────────────────────
  function setScanningState(isScanning) {
    scanBtn.disabled = isScanning;
    scanBtnLabel.textContent = isScanning ? 'Scanning...' : 'Scan for secrets';
  }

  // ── Card builders (all user text via textContent / createElement) ────────────
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function buildResultCard(entry) {
    const riskClass = entry.riskLevel.toLowerCase(); // critical | high | medium
    const card = el('div', `result-card risk-${riskClass}`);

    // header: key + (line chip, badge)
    const header = el('div', 'card-header');
    header.appendChild(el('span', 'var-key', entry.key));

    const meta = el('div', 'card-meta');
    meta.appendChild(el('span', 'line-chip', `Line ${entry.line}`));
    meta.appendChild(el('span', `risk-badge badge-${riskClass}`, entry.riskLevel));
    header.appendChild(meta);
    card.appendChild(header);

    // masked value
    const valueRow = el('div', 'var-value');
    valueRow.appendChild(document.createTextNode('Value: '));
    valueRow.appendChild(el('code', null, entry.maskedValue));
    card.appendChild(valueRow);

    // matched pattern
    const patternRow = el('div', 'matched-pattern');
    patternRow.appendChild(document.createTextNode('Matched pattern: '));
    patternRow.appendChild(el('code', null, `/${entry.matchedRule.pattern}/i`));
    card.appendChild(patternRow);

    // description
    card.appendChild(el('div', 'rule-description', entry.matchedRule.description));

    // remediation
    const rem = el('div', 'remediation-box');
    const remIcon = el('span', 'remediation-icon');
    remIcon.innerHTML = ICONS.bulb; // static markup
    rem.appendChild(remIcon);
    const remText = el('span');
    remText.appendChild(el('strong', null, 'Remediation: '));
    remText.appendChild(document.createTextNode(entry.matchedRule.remediation));
    rem.appendChild(remText);
    card.appendChild(rem);

    return card;
  }

  function buildSafeRow(item) {
    const row = el('div', 'safe-row');
    row.appendChild(el('span', 'safe-row-key', item.key));
    row.appendChild(el('span', 'safe-row-value', item.value));
    row.appendChild(el('span', 'safe-row-line', `Line ${item.line}`));
    return row;
  }

  function buildMeta(results) {
    const flagged = results.critical.length + results.high.length + results.medium.length;
    if (flagged === 0) {
      return `No secrets detected — all ${results.totalScanned} variables look safe`;
    }
    const parts = [];
    if (results.critical.length) parts.push(`${results.critical.length} critical`);
    if (results.high.length) parts.push(`${results.high.length} high`);
    if (results.medium.length) parts.push(`${results.medium.length} medium`);
    const noun = flagged === 1 ? 'secret' : 'secrets';
    return `Found ${flagged} ${noun} — ${parts.join(', ')}`;
  }

  // ── Render ───────────────────────────────────────────────────────────────────
  function renderResults(results) {
    // 1. summary counts
    $('summaryTotal').textContent = results.totalScanned;
    $('summaryCritical').textContent = results.critical.length;
    $('summaryHigh').textContent = results.high.length;
    $('summaryMedium').textContent = results.medium.length;
    $('summarySafe').textContent = results.safe.length;

    // 3. meta line
    resultsMeta.textContent = buildMeta(results);

    // 4. flagged cards, CRITICAL → HIGH → MEDIUM
    resultsList.replaceChildren();
    const ordered = [...results.critical, ...results.high, ...results.medium];
    for (const entry of ordered) {
      resultsList.appendChild(buildResultCard(entry));
    }

    // 6/7. safe variables
    safeList.replaceChildren();
    for (const item of results.safe) {
      safeList.appendChild(buildSafeRow(item));
    }
    const safeNoun = results.safe.length === 1 ? 'variable' : 'variables';
    safeCount.textContent = `${results.safe.length} ${safeNoun} with no secrets detected`;

    // 2. reveal + 8. scroll into view
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  // ── File upload ──────────────────────────────────────────────────────────────
  fileUpload.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      envInput.value = ev.target.result;
    };
    reader.readAsText(file);
    // allow re-uploading the same file name again
    e.target.value = '';
  });

  // ── Clear ────────────────────────────────────────────────────────────────────
  clearBtn.addEventListener('click', () => {
    envInput.value = '';
    hideResults();
    hideError();
    setScanningState(false);
    envInput.focus();
  });

  // ── Scan ─────────────────────────────────────────────────────────────────────
  scanBtn.addEventListener('click', async () => {
    const rawText = envInput.value.trim();
    if (!rawText) {
      showError('Please paste or upload a .env file first.');
      return;
    }

    setScanningState(true);
    hideError();
    hideResults();

    try {
      const results = await scanEnv(rawText);
      renderResults(results);
    } catch (err) {
      showError(err.message);
    } finally {
      setScanningState(false);
    }
  });
});
