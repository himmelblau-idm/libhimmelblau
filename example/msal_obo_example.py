#!/usr/bin/env python3
"""
OBO (On-Behalf-Of) flow example using ConfidentialClientApplication.

This demonstrates acquiring a token for a downstream API on behalf of
a user whose access token you already possess (the "user assertion").

Usage:
    python3 msal_obo_example.py

You will be prompted for:
    - Client ID (the confidential app registration)
    - Client secret
    - Authority URL (e.g. https://login.microsoftonline.com/<tenant>)
    - User assertion (the incoming access token)
    - Scopes for the downstream API
"""

from himmelblau import (
    ConfidentialClientApplication,
    OboInteractionRequiredError,
    TracingLevel,
    set_global_tracing_level,
)
import sys

set_global_tracing_level(TracingLevel.DEBUG)

# Collect configuration
client_id = input("Client ID: ").strip()
client_secret = input("Client secret: ").strip()
authority = input("Authority (e.g. https://login.microsoftonline.com/<tenant>): ").strip()
user_assertion = input("User assertion (the incoming access token): ").strip()
scope = input("Downstream scope (e.g. https://graph.microsoft.com/.default): ").strip()

# Initialize the confidential client
try:
    app = ConfidentialClientApplication(client_id, authority, client_secret)
    print("Confidential client initialized.")
except Exception as e:
    print(f"Failed to initialize confidential client: {e}")
    sys.exit(1)

# Perform the OBO exchange
try:
    obo_token = app.acquire_token_on_behalf_of(user_assertion, [scope])
    print(f"\nOBO exchange successful!")
    print(f"  Access token: {obo_token.access_token[:40]}...")
    print(f"  Token type:   {obo_token.token_type}")
    print(f"  Expires in:   {obo_token.expires_in} seconds")
    if obo_token.scope:
        print(f"  Scope:        {obo_token.scope}")
    if obo_token.refresh_token:
        print(f"  Refresh token: (present)")
    else:
        print(f"  Refresh token: (not returned -- request offline_access scope)")
except OboInteractionRequiredError as e:
    print("\nConditional Access requires user interaction.")
    print("Propagate the claims challenge back to the original caller.")
    print(f"  claims: {getattr(e, 'claims', None)}")
    print(f"  error: {getattr(e, 'error', None)}")
    print(f"  description: {getattr(e, 'error_description', None)}")
    print(f"  error_codes: {getattr(e, 'error_codes', None)}")
    print(f"  suberror: {getattr(e, 'suberror', None)}")
    sys.exit(1)
except Exception as e:
    print(f"\nOBO token acquisition failed: {e}")
    sys.exit(1)

# Bonus: demonstrate client_credentials grant as well
print("\n--- Client credentials grant (app-only) ---")
try:
    client_token = app.acquire_token_silent([scope])
    print(f"  Access token: {client_token.access_token[:40]}...")
    print(f"  Token type:   {client_token.token_type}")
    print(f"  Expires in:   {client_token.expires_in} seconds")
    print(f"  Tenant ID:    {client_token.get_tenant_id()}")
except Exception as e:
    print(f"  Client credentials grant failed: {e}")
