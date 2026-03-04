(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.HWAutofillMatcher = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  function normalizeHost(input) {
    if (!input) return '';
    try {
      const url = input.includes('://') ? new URL(input) : new URL(`https://${input}`);
      return (url.hostname || '').toLowerCase().replace(/^www\./, '');
    } catch (_) {
      return '';
    }
  }

  function scoreEntryForHost(entryName, entryUrl, targetHost) {
    const host = normalizeHost(entryUrl);
    if (!host || !targetHost) return 0;

    if (host === targetHost) return 100;
    if (targetHost.endsWith(`.${host}`) || host.endsWith(`.${targetHost}`)) return 80;
    if ((entryUrl || '').toLowerCase().includes(targetHost)) return 60;
    if ((entryName || '').toLowerCase().includes(targetHost)) return 40;
    return 0;
  }

  function rankMatches(targetHost, candidates) {
    const scored = [];
    for (const c of candidates || []) {
      const score = scoreEntryForHost(c.name || '', c.url || '', targetHost);
      if (score > 0) {
        scored.push({ ...c, score });
      }
    }
    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return (a.name || '').localeCompare(b.name || '');
    });
    return scored;
  }

  function preferExactMatches(matches) {
    const exact = (matches || []).filter((m) => (m.score || 0) >= 100);
    return exact.length ? exact : (matches || []);
  }

  return {
    normalizeHost,
    scoreEntryForHost,
    rankMatches,
    preferExactMatches,
  };
});
