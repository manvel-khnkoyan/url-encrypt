
const tap = require('tap');
const urlEncrypt = require('../index.js');

tap.test('Main', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({ secretKey: '#6h-_hey' });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'validating main functionality');
  t.ok(!encryptor.verify(url.replace(/timestamp=([0-9]+)/, 'timestamp=1573826535')), 'validating invalid url');
  t.end();
});

tap.test('expiredAfterSeconds', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({
    secretKey: '#6h-_hey', expiredAfterSeconds: 4, oversight: 0, prefix: 'prfx_',
  });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'validating expired date');
  setTimeout(() => {
    t.ok(!encryptor.verify(url), 'validating url after expired seconds (5)');
    t.end();
  }, 5000);
});

tap.test('algorithm', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({ secretKey: '#6h-_hey', expiredAfterSeconds: 4, algorithm: 'md5' });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'When is valid');
  t.ok(!encryptor.verify(`DD${url}SS`), 'When is invalid');

  const encryptor2 = urlEncrypt();
  encryptor2.config({ secretKey: '#6h-_hey', expiredAfterSeconds: 4, algorithm: 'sha256' });
  t.ok(encryptor2.verify(url), 'When algorithm is different, should be valid we checking is making by query params, and not by config');

  const encryptor3 = urlEncrypt();
  encryptor3.config({ secretKey: '#6h-_hey', expiredAfterSeconds: 4, algorithm: 'md5' });
  t.ok(encryptor3.verify(url), 'When algorithm the same');

  t.end();
});


tap.test('Initial Config', (t) => {
  const encryptor = urlEncrypt({ secretKey: 'E3' });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'validating initial config by argument');
  t.ok(!encryptor.verify(`DD${url}SS`), 'validating initial config by argument');

  const encryptor2 = urlEncrypt();
  encryptor2.config({ secretKey: 'E3' });
  t.ok(encryptor2.verify(url), 'validating inital config from another encryptor');
  t.end();
});


tap.test('oversight', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({ secretKey: '#6h-_hey', expiredAfterSeconds: 4, oversight: 2 });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'validating oversight main functionality');

  setTimeout(() => {
    t.ok(encryptor.verify(url), 'validating url after expired 3 seconds by: {expiredAfterSeconds: 4, oversight: 2}');
  }, 3000);

  setTimeout(() => {
    t.ok(encryptor.verify(url), 'validating url after expired 5 seconds by: {expiredAfterSeconds: 4, oversight: 2}');
  }, 5000);

  setTimeout(() => {
    t.ok(!encryptor.verify(url), 'validating url after expired 8 seconds by {expiredAfterSeconds: 4, oversight: 2}');
    t.end();
  }, 8000);
});


tap.test('Prefix', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({ secretKey: '#6h-_hey', prefix: 'wow___' });
  const url = encryptor.encrypt('https://example.com/posts/?postId=15');
  t.ok(encryptor.verify(url), 'validating prefix main functionality');

  const encryptor2 = urlEncrypt();
  encryptor2.config({ secretKey: '#6h-_hey', prefix: 'ss__' });
  t.ok(!encryptor2.verify(url), 'Should be invalid for difference prefixes');
  t.end();
});


tap.test('Secret', (t) => {
  const encryptor = urlEncrypt();
  encryptor.config({ secretKey: '#6h-_hey', prefix: 'wow___' });
  const url = encryptor.encrypt('https://example.com/posts?postId=15');
  t.ok(encryptor.verify(url), 'Should be invalid');

  const encryptor2 = urlEncrypt();
  encryptor2.config({ secretKey: '#6h-_hes', prefix: 'wow___' });
  t.ok(!encryptor2.verify(url), 'Should be invalid');

  const encryptor3 = urlEncrypt();
  encryptor3.config({ secretKey: '#6h-_hey', prefix: 'wow___' });
  t.ok(encryptor3.verify(url), 'Should be valid');
  t.end();
});
