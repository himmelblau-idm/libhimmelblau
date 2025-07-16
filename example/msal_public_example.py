"""
Example script that demonstrates using the Python bindings for libhimmelblau to
authenticate with a public client and a chosen MFA method.

The Tenant ID and Client ID can be specified as environment variables, or via
input prompts, along with a username and password.
"""
import os
from himmelblau import PublicClientApplication, TracingLevel, set_global_tracing_level

from getpass import getpass
from time import sleep

TENANT_ID = os.environ.get("TENANT_ID", None) or input("Enter your Azure Tenant ID: ")
PUBLIC_CLIENT_ID = os.environ.get("CLIENT_ID", None) or input("Enter the Public Client ID to use for auth: ")

set_global_tracing_level(TracingLevel.INFO)

authority = f"https://login.microsoftonline.com/{TENANT_ID}"

client = PublicClientApplication(client_id=PUBLIC_CLIENT_ID, authority=authority)

username = input("Please enter your EntraID username: ").strip()

auth_init = client.check_user_exists(username)

if auth_init.exists():
    print(f"User {username} exists!")
else:
    raise ValueError(f"User {username} does not exist!")

password = getpass("Password: ")

scopes = ["offline_access"]

SELECTED_MFA_METHOD = "TwoWayVoiceMobile"  # Can change to other methods like "PhoneAppOTP", "OneWaySMS", etc. - None for default MFA method
MFA_METHODS = ["PhoneAppOTP", "PhoneAppNotification", "OneWaySMS", "ConsolidatedTelephony", "TwoWayVoiceMobile", "TwoWayVoiceOffice"]

if SELECTED_MFA_METHOD not in MFA_METHODS:
    raise ValueError(f"{SELECTED_MFA_METHOD} is not in list of recognized MFA methods")

try:
    if SELECTED_MFA_METHOD:
        print(f"Using MFA method: {SELECTED_MFA_METHOD}")
        flow = client.initiate_acquire_token_by_mfa_flow_with_method(username, password, scopes, None, SELECTED_MFA_METHOD)
    else:
        flow = client.initiate_acquire_token_by_mfa_flow(username, password, scopes, None)
except Exception as e:
    print(e)
    raise

user_token = None

print("Available MFA methods from flow: ", flow.get_available_mfa_methods())
print(f"Default MFA method for flow: {flow.mfa_method}")

print(f"Using MFA method {SELECTED_MFA_METHOD} with max {flow.max_poll_attempts} poll attempts...")

if flow.msg:
    print(flow.msg)

for i in range(0, flow.max_poll_attempts):
    try:
        # poll for success while waiting for the selected MFA method to be evaluated
        user_token = client.acquire_token_by_mfa_flow_with_method(username, flow, None, i, flow.mfa_method)
    except Exception as e:
        print(e)
        if "MFAPollContinue" in str(e):
            sleep(flow.polling_interval/1000)
        else:
            break
    else:
        break

if user_token:
    print(f"Authentication was successful: access_token={user_token.access_token} refresh_token={user_token.refresh_token} tenant={user_token.tenant_id}")
else:
    print("Authentication failed!")
    exit(1)
