from himmelblau import *
from getpass import getpass
import sys
from time import sleep

set_global_tracing_level(TracingLevel.TRACE)

tpm = Tpm()
auth_value = auth_value_generate()
print("auth_value: %s" % auth_value)
loadable_machine_key = tpm.machine_key_create(auth_value)
machine_key = tpm.machine_key_load(auth_value, loadable_machine_key)
client = BrokerClientApplication()
username = input("Please enter your EntraID username: ").strip()
domain = username.split("@")[-1]
if client.check_user_exists(username):
    print("User %s exists!" % username)
else:
    print("User %s does not exist!" % username)
password = getpass("Password: ")

flow = client.initiate_acquire_token_by_mfa_flow_for_device_enrollment(username, password)

sys.stdout.write("%s" % flow.msg)
sys.stdout.flush()

token = None
if flow.mfa_method in ["PhoneAppOTP", "OneWaySMS", "ConsolidatedTelephony"]:
    otp = getpass("")
    token = client.acquire_token_by_mfa_flow(username, flow, auth_data=otp)
else:
    print()
    for i in range(0, flow.max_poll_attempts):
        try:
            token = client.acquire_token_by_mfa_flow(username, flow, poll_attempt=i)
        except Exception as e:
            if "MFAPollContinue" in str(e):
                sleep(flow.polling_interval/1000)
            else:
                break
        else:
            break
if token:
    print("Authentication was successful!")
else:
    exit(1)

attrs = EnrollAttrs(domain, "msal_example_py")
(transport_key, cert_key, device_id) = client.enroll_device(token.refresh_token, attrs, tpm, machine_key)

print("Enrolled with device id: %s" % device_id)

print("Obtain PRT from enrollment refresh token")
token0 = client.acquire_token_by_refresh_token(token.refresh_token, [], tpm, machine_key)
print("access_token: %s, spn: %s, uuid: %s, mfa?: %d" % (token0.access_token, token0.spn, token0.uuid, token0.amr_mfa))

print("Provision hello key")
hello_key = client.provision_hello_for_business_key(token, tpm, machine_key, "123456")

print("Acquire token via hello key")
token0 = client.acquire_token_by_hello_for_business_key(username, hello_key, [], tpm, machine_key, "123456")
print("access_token: %s, spn: %s, uuid: %s, mfa?: %d" % (token0.access_token, token0.spn, token0.uuid, token0.amr_mfa))

print("Acquiring a PRT SSO Cookie")
cookie = client.acquire_prt_sso_cookie(token0.prt, tpm, machine_key)
print("cookie:", cookie)

print("Unseal the TGT from the PRT")
(cloud_tgt, client_key) = client.unseal_cloud_tgt(token0.prt, tpm, machine_key)

print("Parse the TGT into a Kerberos ccache")
ccache = CCache(cloud_tgt.message, client_key)
ccache.save_keytab_file('./test_ccache')
with open('./test_ccache', 'rb') as c:
    print(c.read())

print("Unseal the Kerberos top level names")
kerberos_top_level_names = client.unseal_prt_kerberos_top_level_names(token0.prt, tpm, machine_key)
print(kerberos_top_level_names)
