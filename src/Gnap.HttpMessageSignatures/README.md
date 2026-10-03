# Gnap.HttpMessageSignatures

HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and Digest
Fields ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)) for .NET. Standalone: usable
without GNAP.

- Signature base canonicalization (all derived components, `sf`/`key`/`bs`/`tr`/`req`
  parameters, RFC 8941 structured fields)
- Signing and verification: `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`,
  `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`
- Verifier with multi-signature support, `created`/`expires` windows, clock skew, max age,
  required components, alg/key mismatch protection and nonce replay protection
- `Content-Digest` (`sha-256`, `sha-512`) creation and verification
- `HttpSignatureDelegatingHandler` that signs every outgoing `HttpClient` request
- Verified against all RFC 9421 Appendix B test vectors

## Sign outgoing requests

```csharp
using Gnap.HttpMessageSignatures;

var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(pemText);
var signer = new HttpMessageSigner(SignatureAlgorithm.Ed25519(publicKey, privateKey))
{
    KeyId = "my-client",
    CoveredComponents =
    [
        SignatureComponent.Method,
        SignatureComponent.TargetUri,
        SignatureComponent.ContentDigest,
    ],
    Lifetime = TimeSpan.FromMinutes(5),
};

using var client = new HttpClient(new HttpSignatureDelegatingHandler(signer, new SocketsHttpHandler()));
// Every request now carries Content-Digest, Signature-Input and Signature fields.
```

To verify requests in ASP.NET Core, add
[`Gnap.HttpMessageSignatures.AspNetCore`](https://www.nuget.org/packages/Gnap.HttpMessageSignatures.AspNetCore).

## Documentation

- [HTTP Message Signatures for Dummies](https://github.com/mszkb/gnap.net/blob/main/docs/how-it-works.md)
- [Repository and further guides](https://github.com/mszkb/gnap.net)
- [Security policy](https://github.com/mszkb/gnap.net/blob/main/SECURITY.md)

Ed25519 uses [BouncyCastle](https://www.bouncycastle.org/csharp/) (the only dependency);
everything else uses `System.Security.Cryptography`. License: MIT.
