(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.HWPasswordUtils = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  function generateSecurePassword(length = 24) {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{};:,.?';
    const all = lower + upper + digits + symbols;

    const pick = (chars) => chars[crypto.getRandomValues(new Uint32Array(1))[0] % chars.length];
    const out = [pick(lower), pick(upper), pick(digits), pick(symbols)];

    while (out.length < length) out.push(pick(all));

    for (let i = out.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      const t = out[i];
      out[i] = out[j];
      out[j] = t;
    }
    return out.join('');
  }

  function passwordMeetsBaseline(p) {
    if (typeof p !== 'string' || p.length < 12) return false;
    return /[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p);
  }

  return { generateSecurePassword, passwordMeetsBaseline };
});
