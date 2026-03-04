const test = require('node:test');
const assert = require('node:assert/strict');

global.crypto = require('node:crypto').webcrypto;
const { generateSecurePassword, passwordMeetsBaseline } = require('../password_utils');

test('generateSecurePassword has expected length and charset baseline', () => {
  const p = generateSecurePassword(24);
  assert.equal(p.length, 24);
  assert.equal(passwordMeetsBaseline(p), true);
});

test('generateSecurePassword generates different values', () => {
  const p1 = generateSecurePassword(24);
  const p2 = generateSecurePassword(24);
  assert.notEqual(p1, p2);
});

test('passwordMeetsBaseline rejects weak passwords', () => {
  assert.equal(passwordMeetsBaseline('short1A!'), false);
  assert.equal(passwordMeetsBaseline('alllowercase123!'), false);
  assert.equal(passwordMeetsBaseline('ALLUPPERCASE123!'), false);
  assert.equal(passwordMeetsBaseline('NoSymbols1234'), false);
});
