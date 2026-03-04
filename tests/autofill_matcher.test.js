const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeHost, scoreEntryForHost, rankMatches, preferExactMatches } = require('../autofill_matcher');

test('normalizeHost handles urls and hostnames', () => {
  assert.equal(normalizeHost('https://www.Example.com/login'), 'example.com');
  assert.equal(normalizeHost('sub.example.com'), 'sub.example.com');
  assert.equal(normalizeHost('http://localhost:3000/foo'), 'localhost');
  assert.equal(normalizeHost('not a url with spaces'), '');
});

test('scoreEntryForHost prioritizes exact then subdomain matches', () => {
  assert.equal(scoreEntryForHost('a', 'https://example.com', 'example.com'), 100);
  assert.equal(scoreEntryForHost('a', 'https://example.com', 'app.example.com'), 80);
  assert.equal(scoreEntryForHost('a', 'https://app.example.com', 'example.com'), 80);
  assert.equal(scoreEntryForHost('example', 'https://other-site.com/path/example.com', 'example.com'), 60);
  assert.equal(scoreEntryForHost('my example.com acct', '', 'example.com'), 0);
});

test('rankMatches returns sorted matches only', () => {
  const out = rankMatches('example.com', [
    { name: 'B', url: 'https://sub.example.com' },
    { name: 'A', url: 'https://example.com/login' },
    { name: 'C', url: 'https://nope.com' },
  ]);

  assert.equal(out.length, 2);
  assert.equal(out[0].name, 'A');
  assert.equal(out[0].score, 100);
  assert.equal(out[1].name, 'B');
  assert.equal(out[1].score, 80);
});

test('preferExactMatches keeps only exact when available', () => {
  const matches = [
    { name: 'a', score: 80 },
    { name: 'b', score: 100 },
    { name: 'c', score: 60 },
  ];
  const out = preferExactMatches(matches);
  assert.equal(out.length, 1);
  assert.equal(out[0].name, 'b');
});

test('preferExactMatches keeps all when no exact exists', () => {
  const matches = [
    { name: 'a', score: 80 },
    { name: 'c', score: 60 },
  ];
  const out = preferExactMatches(matches);
  assert.equal(out.length, 2);
});
