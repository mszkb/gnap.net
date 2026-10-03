// Cross-implementation HTTP Message Signature checks (RFC 9421 / RFC 9530) for
// Gnap.Interop.Tests. Two independent JavaScript implementations take part:
//   - "library": http-message-signatures (dhensby), a generic RFC 9421 implementation
//   - "rafiki":  @interledger/http-signature-utils, the verifier/signer Rafiki uses
//                (Ed25519 only, label "sig1")
//
//   node crosscheck.mjs verify < {alg, jwk, request:{method,url,headers,body}}
//     -> {library: bool, rafiki: bool|null, digest: bool|null}
//   node crosscheck.mjs sign   < {alg, digest, request:{method,url,headers,body}}
//     -> {jwk, library: request, rafiki: request|null}
import crypto from 'node:crypto';
import { httpbis, createSigner, createVerifier } from 'http-message-signatures';
import { validateSignature, createSignatureHeaders } from '@interledger/http-signature-utils';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const mode = process.argv[2];

const lower = (headers) => Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
const digestAlgs = { 'sha-256': 'sha256', 'sha-512': 'sha512' };

function checkDigest(request) {
  const header = lower(request.headers)['content-digest'];
  if (!header || request.body === undefined || request.body === null) return null;
  return header.split(',').map((m) => m.trim()).every((member) => {
    const [, name, value] = /^([a-z0-9-]+)=:([^:]*):$/.exec(member) ?? [];
    if (!digestAlgs[name]) return true; // unknown algorithms are ignored (RFC 9530 Section 2)
    return crypto.createHash(digestAlgs[name]).update(request.body, 'utf8').digest('base64') === value;
  });
}

if (mode === 'verify') {
  const { alg, jwk, request } = input;
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  let library;
  try {
    library = (await httpbis.verifyMessage(
      { keyLookup: async () => ({ id: jwk.kid, algs: [alg], verify: createVerifier(publicKey, alg) }) },
      { method: request.method, url: request.url, headers: request.headers },
    )) === true;
  } catch (e) {
    library = false;
    process.stderr.write(`library: ${e.message}\n`);
  }

  let rafiki = null;
  if (alg === 'ed25519') {
    try {
      rafiki = await validateSignature(jwk, {
        method: request.method,
        url: request.url,
        headers: lower(request.headers),
        body: request.body ?? undefined,
      });
    } catch (e) {
      rafiki = false;
      process.stderr.write(`rafiki: ${e.message}\n`);
    }
  }

  console.log(JSON.stringify({ library, rafiki, digest: checkDigest(request) }));
} else if (mode === 'sign') {
  const { alg, digest, request } = input;
  const { publicKey, privateKey } = alg === 'ed25519'
    ? crypto.generateKeyPairSync('ed25519')
    : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = `node-${alg}`;
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: alg === 'ed25519' ? 'EdDSA' : 'ES256' };

  const headers = { ...request.headers };
  const fields = ['@method', '@target-uri'];
  if (request.body) {
    const name = digest ?? 'sha-256';
    headers['Content-Digest'] = `${name}=:${crypto.createHash(digestAlgs[name]).update(request.body, 'utf8').digest('base64')}:`;
    fields.push('content-digest');
  }
  if (headers['Authorization']) fields.push('authorization');

  const signed = await httpbis.signMessage(
    {
      key: createSigner(privateKey, alg, kid),
      name: 'sig1',
      params: ['created', 'keyid', 'nonce', 'tag'],
      paramValues: { nonce: crypto.randomBytes(12).toString('base64url'), tag: 'gnap' },
      fields,
    },
    { method: request.method, url: request.url, headers },
  );

  let rafiki = null;
  if (alg === 'ed25519') {
    const rafikiHeaders = lower(headers);
    if (request.body) {
      rafikiHeaders['content-type'] ??= 'application/json';
      rafikiHeaders['content-length'] = String(Buffer.byteLength(request.body));
    }
    const sig = await createSignatureHeaders({
      request: { method: request.method, url: request.url, headers: rafikiHeaders, body: request.body },
      privateKey,
      keyId: kid,
    });
    rafiki = { method: request.method, url: request.url, headers: { ...rafikiHeaders, ...sig }, body: request.body };
  }

  console.log(JSON.stringify({
    jwk,
    library: { method: request.method, url: request.url, headers: signed.headers, body: request.body },
    rafiki,
  }));
} else {
  console.error('usage: node crosscheck.mjs verify|sign < input.json');
  process.exit(2);
}
