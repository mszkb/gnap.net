# Gnap.HttpMessageSignatures.AspNetCore

ASP.NET Core middleware that verifies HTTP Message Signatures
([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and `Content-Digest` fields
([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)) on incoming requests, built on
[`Gnap.HttpMessageSignatures`](https://www.nuget.org/packages/Gnap.HttpMessageSignatures).

```csharp
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;

builder.Services.AddHttpMessageSignatureVerification(options =>
{
    options.KeyResolver = new StaticKeyResolver().Add("my-client", SignatureAlgorithm.Ed25519(publicKey));
    options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];

    // Optional replay protection (RFC 9421 §7.2.2): each nonce is accepted once per keyid.
    options.NonceStore = new InMemoryNonceStore();
    options.RequireNonce = true;
});

app.UseHttpMessageSignatureVerification();
```

Unsigned, tampered, expired or replayed requests are rejected with `401` before they reach
your endpoints. Nonces are recorded only after the signature verified, so forged requests
cannot "burn" a legitimate client's nonce. `InMemoryNonceStore` suits a single process;
implement `INonceStore` over a shared cache for multi-instance deployments.

For GNAP resource servers use [`Gnap.AspNetCore`](https://www.nuget.org/packages/Gnap.AspNetCore),
which verifies key-bound GNAP access tokens on top of this middleware's primitives.

More: [github.com/mszkb/gnap.net](https://github.com/mszkb/gnap.net). License: MIT.
