#!/usr/bin/env bash
# Build a throwaway "home directory" full of INERT, obviously-fake credentials
# so the README demo can show a realistic report without touching anyone's real
# secrets. Every token is a FAKEBLAST filler or a published, non-functional
# example value; the SSH key is generated at record time and never committed.
# blastradius only ever prints a SHA-256 fingerprint, never the secret itself.
set -euo pipefail

home="${1:?usage: make-demo-home.sh <dir>}"
rm -rf "$home"
mkdir -p "$home/.aws" "$home/.config/gh" "$home/.ssh" "$home/.kube" \
  "$home/.docker" "$home/.claude" "$home/src/api"

# A fake token of a given prefix, padded to a length with low-entropy filler so
# no secret scanner mistakes it for a live credential.
tok() { local p="$1" n="$2" s="$1"; while [ ${#s} -lt "$n" ]; do s="${s}FAKEBLAST"; done; printf '%s' "${s:0:$n}"; }

# AWS: a long-term access key. AKIAIOSFODNN7EXAMPLE and the matching secret are
# AWS's own published, non-functional documentation examples.
cat > "$home/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[admin]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = default
EOF

# npm: a legacy, never-expiring token.
echo "//registry.npmjs.org/:_authToken=$(tok npm_ 40)" > "$home/.npmrc"

# GitHub: the same OAuth token stored in three places (gh, git-credentials, and
# later in a .env) so the report shows duplicate-secret correlation.
ghtok="$(tok gho_ 40)"
cat > "$home/.config/gh/hosts.yml" <<EOF
github.com:
    user: alice
    oauth_token: $ghtok
    git_protocol: https
EOF
echo "https://alice:$ghtok@github.com" > "$home/.git-credentials"

# SSH: a real, passphrase-less key generated at record time (not committed).
if command -v ssh-keygen >/dev/null 2>&1; then
  ssh-keygen -t ed25519 -N "" -C "demo@blastradius" -f "$home/.ssh/id_ed25519" >/dev/null 2>&1
fi
chmod 600 "$home/.ssh/id_ed25519" 2>/dev/null || true
cat > "$home/.ssh/config" <<'EOF'
Host prod
  HostName prod.example.com
  User deploy
  ForwardAgent yes
EOF

# Kubernetes: a static bearer token in a context.
cat > "$home/.kube/config" <<EOF
apiVersion: v1
kind: Config
current-context: prod
clusters:
- cluster: {server: https://10.0.0.1}
  name: prod
contexts:
- context: {cluster: prod, user: deploy}
  name: prod
users:
- name: deploy
  user: {token: $(tok kubetok 48)}
EOF

# Docker: a plaintext base64 "user:pass" auth entry.
auth=$(printf 'alice:%s' "$(tok dckr 20)" | base64 | tr -d '\n')
cat > "$home/.docker/config.json" <<EOF
{"auths": {"ghcr.io": {"auth": "$auth"}}}
EOF

# Claude Code credentials.
echo "{\"claudeAiOauth\": {\"accessToken\": \"$(tok sk-ant-oat01- 60)\"}}" > "$home/.claude/.credentials.json"

# A project .env that also repeats the GitHub token.
cat > "$home/src/api/.env" <<EOF
DATABASE_URL=postgres://app:$(tok dbpw 24)@db.internal:5432/app
GITHUB_TOKEN=$ghtok
STRIPE_SECRET_KEY=$(tok sk_live_ 40)
EOF

echo "demo home written to $home"
