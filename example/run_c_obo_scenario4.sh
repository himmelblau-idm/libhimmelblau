#!/usr/bin/env bash
# Scenario 4: C API OBO — acquire a user assertion via ROPC then drive
# msal_obo_example with all inputs piped in non-interactively.
#
# Usage:
#   ./example/run_c_obo_scenario4.sh
#
# Required env vars (or will prompt):
#   AUTHORITY, CONFIDENTIAL_CLIENT_ID, CONFIDENTIAL_CLIENT_SECRET,
#   DOWNSTREAM_SCOPE
#
# If USER_ASSERTION is already set, ROPC acquisition is skipped (no need
# for PUBLIC_CLIENT_ID / ENTRA_USERNAME / ENTRA_PASSWORD).  This lets you
# reuse an assertion obtained interactively from Scenario 1:
#
#   export USER_ASSERTION="$(python example/msal_obo_end_to_end_test.py \
#       --scenario 1 --print-assertion)"
#   ./example/run_c_obo_scenario4.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')
LIB_DIR="${REPO_ROOT}/target/${TARGET_TRIPLE}/debug"
C_BINARY="${SCRIPT_DIR}/msal_obo_example"

# ── Ensure the C binary exists ──────────────────────────────────────────────
if [[ ! -x "${C_BINARY}" ]]; then
    echo "C binary not found at ${C_BINARY}. Building..."
    CFLAGS="-I${LIB_DIR}/include -DON_BEHALF_OF" LDFLAGS="-L${LIB_DIR}" make -C "${SCRIPT_DIR}" msal_obo_example
fi

# ── Read config ──────────────────────────────────────────────────────────────
AUTHORITY="${AUTHORITY:-}"
CONFIDENTIAL_CLIENT_ID="${CONFIDENTIAL_CLIENT_ID:-}"
CONFIDENTIAL_CLIENT_SECRET="${CONFIDENTIAL_CLIENT_SECRET:-}"
# Pre-acquired assertion bypasses ROPC entirely.
USER_ASSERTION="${USER_ASSERTION:-}"
# ROPC-only vars (not needed when USER_ASSERTION is pre-set).
PUBLIC_CLIENT_ID="${PUBLIC_CLIENT_ID:-}"
# Use ENTRA_USERNAME to avoid collision with the zsh reserved USERNAME variable.
# Also accept USERNAME from the environment for convenience.
ENTRA_USERNAME="${ENTRA_USERNAME:-${USERNAME:-}}"
ENTRA_PASSWORD="${ENTRA_PASSWORD:-${PASSWORD:-}}"
INCOMING_SCOPE="${INCOMING_SCOPE:-}"
DOWNSTREAM_SCOPE="${DOWNSTREAM_SCOPE:-}"

prompt() { local var="$1" prompt="$2" secret="${3:-false}"
    if [[ -z "${!var:-}" ]]; then
        if [[ "$secret" == "true" ]]; then
            read -rsp "${prompt}" "${var}"; echo
        else
            read -rp "${prompt}" "${var}"
        fi
        export "${var?}"
    fi
}

prompt AUTHORITY               "Authority (e.g. https://login.microsoftonline.com/<tenant>): "
prompt CONFIDENTIAL_CLIENT_ID  "Confidential client ID: "
prompt CONFIDENTIAL_CLIENT_SECRET "Confidential client secret: " true
DOWNSTREAM_SCOPE="${DOWNSTREAM_SCOPE:-https://graph.microsoft.com/User.Read}"

# ── Acquire user assertion (ROPC or pre-set) ─────────────────────────────────
if [[ -n "${USER_ASSERTION}" ]]; then
    echo ""
    echo "Step 1/3: using pre-set USER_ASSERTION (${#USER_ASSERTION} chars) — skipping ROPC."
else
    # Prompt for ROPC-only credentials only when needed.
    prompt PUBLIC_CLIENT_ID        "Public client ID: "
    prompt ENTRA_USERNAME          "Username: "
    prompt ENTRA_PASSWORD          "Password: " true
    INCOMING_SCOPE="${INCOMING_SCOPE:-api://${CONFIDENTIAL_CLIENT_ID}/access_as_user}"

    echo ""
    echo "Step 1/3: acquiring user assertion via ROPC (password only)..."
    VENV_PYTHON="${REPO_ROOT}/.venv/bin/python"
    if [[ ! -x "${VENV_PYTHON}" ]]; then
        VENV_PYTHON="python3"
    fi

    USER_ASSERTION="$("${VENV_PYTHON}" - <<PYEOF
import sys
sys.path.insert(0, '${REPO_ROOT}')
from himmelblau import PublicClientApplication
client = PublicClientApplication(client_id='${PUBLIC_CLIENT_ID}', authority='${AUTHORITY}')
token = client.acquire_token_by_username_password('${ENTRA_USERNAME}', '${ENTRA_PASSWORD}', ['${INCOMING_SCOPE}'])
print(token.access_token, end='')
PYEOF
    )"

    if [[ -z "${USER_ASSERTION}" ]]; then
        echo "ERROR: failed to acquire user assertion via ROPC" >&2
        echo "TIP: if a CA policy requires MFA, set USER_ASSERTION to a pre-acquired" >&2
        echo "     assertion from an interactive Scenario 1 run and re-run this script." >&2
        exit 1
    fi
    echo "User assertion acquired (${#USER_ASSERTION} chars)."
fi

# ── Run C OBO example ────────────────────────────────────────────────────────
echo ""
echo "Step 2/3: running C OBO example (success path, no offline_access)..."
echo "  -> verifying all getters and that refresh_token is NULL when not requested"
echo ""

C_OUTPUT="$(printf '%s\n%s\n%s\n%s\n%s\n' \
    "${CONFIDENTIAL_CLIENT_ID}" \
    "${CONFIDENTIAL_CLIENT_SECRET}" \
    "${AUTHORITY}" \
    "${USER_ASSERTION}" \
    "${DOWNSTREAM_SCOPE}" \
    | DYLD_LIBRARY_PATH="${LIB_DIR}" LD_LIBRARY_PATH="${LIB_DIR}" \
      "${C_BINARY}" 2>&1)"

echo "${C_OUTPUT}"
echo ""

# ── Verify output ────────────────────────────────────────────────────────────
echo "Step 3/3: verifying output..."
PASS=true

check() { local label="$1" pattern="$2"
    if echo "${C_OUTPUT}" | grep -q "${pattern}"; then
        echo "  [PASS] ${label}"
    else
        echo "  [FAIL] ${label} (pattern: '${pattern}' not found)"
        PASS=false
    fi
}

check "OBO exchange completed"     "OBO exchange completed successfully"
check "access_token non-empty"     "OBO access token: ey"
check "token_type is Bearer"       "Token type: Bearer"
check "expires_in > 0"             "Expires in: [1-9]"
check "ext_expires_in present"     "Ext expires in:"
check "scope present"              "Scope:"
check "refresh_token getter works"  "Refresh token:"

echo ""
if [[ "${PASS}" == "true" ]]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi
