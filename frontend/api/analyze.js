// ChainGuard — Vercel Serverless Function (plain JS, zero deps)

function lineOf(source, idx) {
  return source.substring(0, idx).split('\n').length;
}
function snip(source, line) {
  return (source.split('\n')[line - 1] || '').trim();
}
function solidityMinor(source) {
  const m = source.match(/pragma\s+solidity\s+[^;]*?0\.(\d+)/);
  return m ? parseInt(m[1], 10) : 8;
}
function contractName(source) {
  const m = source.match(/contract\s+(\w+)/);
  return m ? m[1] : 'UnknownContract';
}

function detectReentrancy(source) {
  const results = [];
  const fnRe = /function\s+(\w+)\s*\([^)]*\)[^{]*\{/g;
  let m;
  while ((m = fnRe.exec(source)) !== null) {
    const start = m.index + m[0].length;
    let depth = 1, i = start;
    while (i < source.length && depth > 0) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') depth--;
      i++;
    }
    const body = source.slice(start, i - 1);
    const callMatch = body.match(/\.(call|send)\s*[({]/);
    if (!callMatch) continue;
    const callPos = body.indexOf(callMatch[0]);
    const afterCall = body.slice(callPos);
    if (!/balances\[|deposits\[|\w+\s*=\s*0/.test(afterCall)) continue;
    const line = lineOf(source, m.index);
    results.push({
      id: 'reentrancy-' + line,
      title: 'Reentrancy Vulnerability',
      severity: 'HIGH',
      swcId: 'SWC-107',
      description: 'Function "' + m[1] + '" performs an external call before updating state. An attacker can re-enter and drain funds (TheDAO-style attack).',
      recommendation: 'Use Checks-Effects-Interactions: update all state BEFORE external calls. Add OpenZeppelin ReentrancyGuard.',
      line,
      snippet: snip(source, line),
    });
  }
  return results;
}

function detectTxOrigin(source) {
  const results = [];
  const re = /(?:require\s*\(|if\s*\()[^;)]*tx\.origin[^;)]*[;)]/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(source)) !== null) {
    const line = lineOf(source, m.index);
    if (seen.has(line)) continue;
    seen.add(line);
    results.push({
      id: 'txorigin-' + line,
      title: 'Authorization via tx.origin',
      severity: 'HIGH',
      swcId: 'SWC-115',
      description: 'tx.origin is the original transaction initiator. A malicious intermediate contract can bypass this check by tricking the legitimate owner.',
      recommendation: 'Replace tx.origin with msg.sender for all authorization checks.',
      line,
      snippet: snip(source, line),
    });
  }
  return results;
}

function detectOverflow(source) {
  const results = [];
  const minor = solidityMinor(source);
  if (minor >= 8) return results;
  const re = /\w+\s*(\+=|-=|\*=)/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(source)) !== null) {
    const line = lineOf(source, m.index);
    if (seen.has(line)) continue;
    const s = snip(source, line);
    if (s.toLowerCase().includes('safemath')) continue;
    seen.add(line);
    results.push({
      id: 'overflow-' + line,
      title: 'Integer Overflow / Underflow',
      severity: 'HIGH',
      swcId: 'SWC-101',
      description: 'Arithmetic in Solidity 0.' + minor + '.x has no built-in overflow protection. Values can silently wrap around.',
      recommendation: 'Use OpenZeppelin SafeMath or upgrade to Solidity >= 0.8.0.',
      line,
      snippet: s,
    });
  }
  return results;
}

function detectUncheckedCall(source) {
  const results = [];
  const lines = source.split('\n');
  lines.forEach((ln, idx) => {
    const t = ln.trim();
    if (/\.(call|send)\s*[({]/.test(t) && !/^\s*(bool|\()/.test(t) && !/=.*\.(call|send)/.test(t)) {
      results.push({
        id: 'unchecked-' + (idx + 1),
        title: 'Unchecked Return Value (.call / .send)',
        severity: 'MEDIUM',
        swcId: 'SWC-104',
        description: '.call()/.send() return a boolean. Ignoring it means silent failures — ETH may not transfer.',
        recommendation: '`(bool ok,) = addr.call{value: v}(""); require(ok, "Failed");`',
        line: idx + 1,
        snippet: t,
      });
    }
  });
  return results;
}

function detectSelfdestruct(source) {
  const results = [];
  const re = /function\s+(\w+)\s*\([^)]*\)\s*(public|external)([^{]*)\{[^}]*selfdestruct/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    const mods = (m[3] || '').toLowerCase();
    if (/only|owner|admin|auth/.test(mods)) continue;
    const line = lineOf(source, m.index);
    results.push({
      id: 'selfdestruct-' + line,
      title: 'Unprotected selfdestruct',
      severity: 'HIGH',
      swcId: 'SWC-106',
      description: 'Function "' + m[1] + '" calls selfdestruct() without access control. Anyone can destroy this contract.',
      recommendation: 'Add onlyOwner or equivalent access control to any function containing selfdestruct().',
      line,
      snippet: snip(source, line),
    });
  }
  return results;
}

function detectVisibility(source) {
  const results = [];
  // Capture everything between ) and { to check for visibility keywords
  const re = /function\s+(\w+)\s*\([^)]*\)([^{;]*)\{/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(source)) !== null) {
    const name = m[1];
    if (['constructor', 'fallback', 'receive'].includes(name) || seen.has(name)) continue;
    const between = m[2] || '';
    // Skip if any visibility keyword is present between ) and {
    if (/\b(public|private|internal|external)\b/.test(between)) continue;
    seen.add(name);
    const line = lineOf(source, m.index);
    results.push({
      id: 'visibility-' + name + '-' + line,
      title: 'Missing visibility on "' + name + '"',
      severity: 'LOW',
      swcId: 'SWC-100',
      description: 'Function "' + name + '" has no explicit visibility modifier. Defaults to public in Solidity < 0.5.0.',
      recommendation: 'Always specify visibility: public, private, internal, or external.',
      line,
      snippet: snip(source, line),
    });
  }
  return results;
}

function calcScore(vulns) {
  let s = 100;
  for (const v of vulns) {
    if (v.severity === 'HIGH') s -= 20;
    else if (v.severity === 'MEDIUM') s -= 10;
    else if (v.severity === 'LOW') s -= 5;
    else if (v.severity === 'INFO') s -= 1;
  }
  return Math.max(0, s);
}

function analyzeContract(source) {
  const rules = [detectReentrancy, detectTxOrigin, detectOverflow, detectUncheckedCall, detectSelfdestruct, detectVisibility];
  const vulnerabilities = [];
  for (const rule of rules) {
    try { vulnerabilities.push(...rule(source)); } catch (e) { /* continue */ }
  }
  return {
    contractName: contractName(source),
    vulnerabilities,
    totalFound: vulnerabilities.length,
    score: calcScore(vulnerabilities),
    analyzedAt: new Date().toISOString(),
  };
}

// Vercel handler
module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const source = req.body && req.body.source;
    if (!source || typeof source !== 'string' || !source.trim()) {
      return res.status(400).json({ error: 'Body must include a non-empty "source" field.' });
    }
    if (Buffer.byteLength(source, 'utf8') > 50 * 1024) {
      return res.status(413).json({ error: 'Contract source exceeds 50 KB limit.' });
    }
    return res.json(analyzeContract(source));
  } catch (err) {
    return res.status(422).json({ error: err && err.message ? err.message : 'Analysis failed.' });
  }
};
