# If a stealer ran here: how blastradius works

*A `postinstall` script, a VS Code task or a compromised editor extension runs as you
for a few seconds. It does not need root. It reads `~/.npmrc`, `~/.aws/credentials`,
`~/.config/gh/hosts.yml`, your shell history and the environment, and leaves. What did
it get? This write-up covers the attack, the one rule that shaped the tool, how a
machine is rated, and how the optional online probe was built so that it can never
become the exfiltration channel it is warning about.*

---

## 1. The attack

In September 2025 the **Shai-Hulud** worm spread through npm. A maintainer's token was
phished, popular packages were republished with a `postinstall` hook, and every developer
and CI runner that installed them ran the payload. The payload did not exploit anything.
It ran a secret scanner (TruffleHog) over the home directory, read the npm token in
`~/.npmrc`, `GITHUB_TOKEN` from the environment, AWS, GCP and Azure credentials from
their well-known files, and `.env` files. With the npm token it published itself into
every package the victim could publish to, which is what made it a worm. With the GitHub
token it created repositories and workflows to carry the loot out.

A month earlier the **nx** compromise had done the same with a twist: its payload asked
whatever AI coding CLI it found on the machine (Claude Code, Gemini CLI, Amazon Q) to
enumerate secrets for it, so the tools developers trust most did the reading.

Neither attack needed a vulnerability. Both needed only what a normal developer laptop
already has: long-lived tokens in plaintext files, readable by any process running as
the user. The defender's question is therefore not "am I infected?" but **"if that
process ran here today, what would it walk away with?"** That is the question
`blastradius` answers, and the answer is meant to be acted on *before* the process runs:
rotate what is long-lived, shorten what can be short-lived, scope what is broad, and
move what is left into a store that asks before handing a secret out.

It is the second half of a pair. [preflight](https://github.com/howardhsieh/preflight)
asks "will this repository run code on my machine?" and tries to stop the trigger.
blastradius assumes the trigger fired and measures the consequence.

## 2. Design constraints

Four decisions shaped everything else.

**The record never holds the secret.** The `Credential` type has no field that can carry
one. A provider hashes the value the moment it reads it and keeps the first 8 hex
characters of its SHA-256 (the *fingerprint*), which is enough to notice the same token
in three places and to compare two scans, and useless to an attacker. This is enforced
by a test, not a convention: a fixture home directory with more than fifty fake secrets
(every one containing the marker `FAKEBLAST`) is scanned, and every output format is
checked for every secret, its base64 forms, any 16-character fragment, and the marker.
A tool that collects credentials and prints them is a stealer with a nicer README.

**Offline by default, local only.** The scan opens no socket. There is no upload, no
telemetry, no auto-update, no batch or agent mode. The optional probe (section 5) is
the one exception, and it is built so that each secret can travel to exactly one host.

**Zero dependencies.** Everything is Go standard library, including a small YAML subset
parser for kubeconfig and `hosts.yml`, an INI parser for AWS files, and the SigV4 signer
for STS. A security tool's dependency tree is attack surface of exactly the kind it is
auditing, and the tool should be reviewable in an afternoon.

**Read like a stealer, report like an auditor.** The providers open exactly the files a
stealer opens, in the same order of value, and then do what the stealer does not: tell
you what each one unlocks, how long it lives, and how to make it worth less.

## 3. Providers, fingerprints and merging

Sixteen providers cover the usual suspects: the GitHub CLI's `hosts.yml`, git's
`credential.helper=store`, `.netrc`, `.npmrc` (user and project), `.pypirc` and
`pip.conf`, AWS credentials and the SSO and CLI caches, gcloud's application default
credentials and service-account keys, Azure's MSAL cache and service principals,
Docker's `config.json`, kubeconfig, SSH private keys and `ssh_config`, the credential
files of AI coding tools, the process environment, shell start-up files, shell history,
and `.env` files under directories you name.

Each one produces credentials with a **service** (what it unlocks), a **kind** (the shape
of the secret), a **lifetime** (`long-term` until revoked, `short-term` with an expiry
when the file says), an **age** where the file's modification time means something, and
a **severity**. Classification is by shape first (`ghp_`, `npm_`, `AKIA`, `sk-ant-`, a
UUID in `.npmrc` is a legacy npm token that never expires and skips 2FA) and by variable
name second (`AWS_SECRET_ACCESS_KEY`, `*_TOKEN`), with a placeholder filter so that
`your-key-here` and `${VAR}` are not findings.

Because the fingerprint is stable, the same token found in `hosts.yml`, `.git-credentials`
and `$GH_TOKEN` becomes **one row with three locations**, and the advice says "the same
secret is stored in 2 other places" instead of listing the token three times.

## 4. Rating and advice

The rating follows the worst credential: CRITICAL for a long-term cloud key,
service-account key, live payment key or legacy npm token; HIGH for long-lived tokens
with write access to source, packages or infrastructure; MODERATE when what was found is
short-lived or narrow; LOW otherwise. A separate 0–100 exposure score adds everything up
so that two machines with the same rating can still be compared. Expired credentials do
not count.

Advice is grouped by the **fix**, not by the finding. An ordered rule table maps each
credential to the one remediation that removes it (rotate the AWS key and move to SSO;
revoke the legacy npm token today; add a passphrase to the SSH key; stop exporting keys in
`.zshrc`), groups are ordered by the worst credential they cover, and the result is a
short "Do first" list rather than fifty lines of "rotate this".

## 5. The probe, and keeping it honest

Offline, severity is what the credential's *format* allows. A `ghp_` token may be
read-only; an `npm_` token may be granular and package-scoped; an `AKIA` key may belong
to a locked-down IAM user or to the account root. `--probe` asks each service what *this*
credential can do, and refines the severity with the answer: a GitHub token with `repo`
and `admin:org` stays HIGH and says so; a read-only npm token drops to MEDIUM; an npm
automation token that publishes without 2FA becomes CRITICAL; a key whose ARN is the
account root becomes CRITICAL with its own advice; a credential the service rejects
drops to LOW, because a revoked token on disk is clutter, not exposure.

The probe is where a credential inventory tool is most likely to go wrong, so it was
designed around the ways it could:

- **It could send a secret to the wrong place.** Every host a probe may contact is
  hard-coded: `api.github.com`, `registry.npmjs.org`, `sts.amazonaws.com`,
  `api.anthropic.com`, `api.openai.com`. Each HTTP client is wrapped in a transport that
  refuses any other host, HTTPS only, and follows no redirects, so a bug in a prober
  cannot reach somewhere else. Kubernetes has no fixed list, because the API server is
  whatever the kubeconfig says, and a writable or stale kubeconfig could turn a probe
  into token delivery; so each cluster must be named with `--probe-cluster`, and the
  request is verified against the cluster's own CA. GitHub Enterprise hosts work the
  same way with `--probe-host`.
- **It could send the wrong secret.** The credential record carries no secret, so the
  prober re-reads it from the recorded location and line at probe time, and accepts the
  value only if its SHA-256 matches the fingerprint the scan recorded. A token rotated
  between scan and probe is not sent.
- **The service could echo the secret back.** A hostile or broken API that returns the
  token as the "login" would otherwise put it in the report. Everything a service
  returns is scrubbed against the secret, its base64 forms and sliding 16- and
  8-character fragments before it is kept. The leak test runs a third time against a
  fake API that does exactly this, in every field.
- **It could be invisible.** Before the first request leaves the machine, the exact list
  of hosts and how many credentials of which service go to each is printed. With nothing
  to probe, no request is made, and a test proves it.
- **It could hang or fail loudly.** Ten seconds per probe, sixty for the phase, failures
  become "not probed" lines, and the offline result is always there.

The AWS probe signs `sts:GetCallerIdentity` with a hand-rolled SigV4 (about a hundred
lines of `crypto/hmac`) rather than the SDK, to keep the zero-dependency rule. It is
tested against the key-derivation vector in the AWS documentation and against
signatures generated with botocore for the exact request the tool sends.

## 6. What it does not do

- It reads **well-known locations**. A token in `~/notes/todo.txt` is not found; `--dir`
  covers project trees, and a general secret scanner covers everything else.
- OS keychains are not opened. A `gh` login whose token lives in the macOS Keychain is
  reported LOW with a note, because a process running as you can still ask for it.
- Encrypted keys are not decrypted; "passphrase-protected" is read from the key header.
- GitHub fine-grained PAT permissions are not introspectable through the API, so a probed
  fine-grained token is reported as live and fine-grained, not as read-only.
- It does not prove the machine is clean. It proves what a stealer would find in the
  places stealers look.

## 7. Using it

```bash
blastradius scan                              # home directory + environment, offline
blastradius scan --dir ~/src                  # also .env files and project .npmrc
blastradius scan --probe --probe-cluster prod # ask the services what each token can do
blastradius scan -f json -o report.json       # machine-readable, mode 0600
blastradius scan -f sarif -o blastradius.sarif  # one result per credential, for dashboards
blastradius scan --fail-on high               # exit 1 for a pre-commit or CI self-check
```

Treat a report as sensitive: fingerprints identify secrets even if they cannot be used.
