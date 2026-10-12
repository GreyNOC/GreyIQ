# Code signing the Windows build

By default the GreyIQ Windows portable and installer are **unsigned**. Windows
SmartScreen shows a blue "Windows protected your PC" warning the first time an
unsigned `.exe` is run, and many users will not click through it. Signing the
binaries with an Authenticode certificate removes (or, for OV certs, eventually
removes) that warning.

The release pipeline is **already signing-ready**: when the signing secrets are
present it signs automatically; when they are absent the build is unchanged
(unsigned). You do **not** need to edit any workflow or code — you only add two
repository secrets once you have a certificate.

## What you need

An **Authenticode code-signing certificate**. Two tiers, and the difference
matters for SmartScreen:

| Cert type | Cost | SmartScreen behavior |
|---|---|---|
| **OV** (Organization Validation) | ~$200–400/yr | Still warns at first, then the warning fades as the signed binary builds *download reputation* over time/installs. |
| **EV** (Extended Validation) | ~$300–600/yr | **Immediate** SmartScreen pass — reputation is granted to the cert on day one. Private key lives on a hardware token / cloud HSM. |

If immediate trust matters, get **EV**. If you can tolerate a ramp-up, **OV** is
cheaper and simpler to automate (a plain `.pfx` file).

Issuers: DigiCert, Sectigo/Comodo, GlobalSign, SSL.com, etc.

## Option A — OV `.pfx` via repo secrets (simplest to automate)

1. Obtain the cert and export it as a password-protected `.pfx` (PKCS#12) file
   containing the private key + full chain.
2. Base64-encode the `.pfx`:
   - PowerShell: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("greyiq.pfx")) | Set-Content cert.b64`
   - bash: `base64 -w0 greyiq.pfx > cert.b64`
3. In the GitHub repo, add two **Actions secrets**
   (Settings → Secrets and variables → Actions):
   - `WINDOWS_CSC_LINK` — the base64 string from step 2.
   - `WINDOWS_CSC_KEY_PASSWORD` — the `.pfx` password.
4. Cut a release as usual (`git tag vX.Y.Z && git push origin vX.Y.Z`). The
   Windows job picks the secrets up as `CSC_LINK` / `CSC_KEY_PASSWORD`,
   electron-builder signs the portable, the installer, and the inner app `.exe`,
   and the **"Report Authenticode signing status"** step verifies every `.exe`
   shows `Valid` (the build fails if signing was requested but a signature is
   not valid).

That is the whole change — no workflow edit. The pipeline already maps those
secrets in `.github/workflows/release.yml` and skips signing cleanly when they
are unset.

## Option B — EV / Azure Trusted Signing (no key material in secrets)

EV certs keep the private key on hardware, so a raw `.pfx` is not available.
The modern path is **[Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/)**
(a managed signing service, ~$10/mo, with EV-grade SmartScreen reputation).
electron-builder supports it via `win.azureSignOptions` plus the
`AZURE_*` credential env vars. If you go this route, add an
`azureSignOptions` block under `build.win` in `package.json` and map the
`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` secrets in the
Windows build step's `env:` — mirroring how `CSC_LINK` is mapped today. Ask
before wiring this; it needs an Azure subscription and an approved signing
identity.

## Verifying a signature

- In CI: the **"Report Authenticode signing status"** step prints each `.exe`'s
  signature status and signer subject, and fails the build if a requested
  signature is not `Valid`.
- Locally: `Get-AuthenticodeSignature .\GreyIQ-*.exe | Format-List` (PowerShell),
  or right-click the `.exe` → Properties → Digital Signatures.

## Signing a local build

`npm run build:portable` (and any direct `electron-builder` invocation) also
picks up `CSC_LINK` / `CSC_KEY_PASSWORD` from the environment, so a local signed
build is:

```powershell
$env:CSC_LINK = [Convert]::ToBase64String([IO.File]::ReadAllBytes("greyiq.pfx"))
$env:CSC_KEY_PASSWORD = "<pfx password>"
npm run build:portable -- -Installer
```

Leave those env vars unset for an ordinary unsigned local build.

## Signing and notarizing macOS releases

The release workflow builds a native Apple Silicon DMG/ZIP and a native Intel
DMG/ZIP. They use the GreyIQ icon in `build/icon.icns`. The workflow accepts an
all-or-none set of six Actions secrets:

| Secret | Value |
|---|---|
| `MAC_CSC_LINK` | Base64-encoded Developer ID Application `.p12` certificate |
| `MAC_CSC_KEY_PASSWORD` | Password for the `.p12` |
| `APPLE_API_KEY` | Base64-encoded App Store Connect API key `.p8` file |
| `APPLE_API_KEY_ID` | API key identifier |
| `APPLE_API_ISSUER` | API issuer identifier |
| `APPLE_TEAM_ID` | Apple Developer team identifier |

The macOS job decodes the API key into a private temporary `.p8` file and passes
its path to electron-builder. A partial secret set fails the build. With all six
secrets, electron-builder signs and notarizes the app; CI verifies the code
signature, stapled ticket, and Gatekeeper assessment before uploading either
archive to the draft release. See the [electron-builder v26 notarization guide](https://www.electron.build/v26/docs/notarization/).

When the secrets are absent, CI creates unsigned, unnotarized **draft** archives
and emits a warning. macOS Gatekeeper may block their normal first launch, so
they should not be presented as ready for public distribution. Only the human
operator publishes the reviewed release. The macOS build does not bundle Ollama;
the operator installs it on demand for local coding models.
