/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <himmelblau/himmelblau.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

void strip_newline(char *str) {
	int len = strlen(str);
	if (str[len-1] == '\n') {
		str[len-1] = '\0';
	}
}

void cat_file(const char *filename) {
	FILE *f = fopen(filename, "rb");
	if (f == NULL) {
		printf("Failed opening the ccache for reading\n");
		return;
	}
	int b = 0;
	while ((b = fgetc(f)) != EOF) {
		if (isprint(b)) {
			printf("%c", b);
		} else {
			printf(".");
		}
	}
	fclose(f);
}

int main() {
	BoxedDynTpm *tpm = NULL;
	BrokerClientApplication *client = NULL;
	LoadableMachineKey *loadable_machine_key = NULL;
	MachineKey *machine_key = NULL;
	EnrollAttrs *attrs = NULL;
	MFAAuthContinue *flow = NULL;
	UserToken *token = NULL;
	UserToken *token0 = NULL;
	LoadableMsOapxbcRsaKey *transport_key = NULL;
	LoadableMsDeviceEnrolmentKey *cert_key = NULL;
	LoadableMsHelloKey *hello_key = NULL;
	SealedData *prt = NULL;
	MSAL_ERROR *err;
	char* auth_value = NULL;
	char *domain = NULL;
	size_t len;
	char *username = NULL;
	char *password = NULL;
	char *msg = NULL;
	char *mfa_method = NULL;
	char *device_id = NULL;
	char *refresh_token = NULL;
	char *access_token = NULL;
	char *spn = NULL;
	char *uuid = NULL;
	char *kerberos_top_level_names = NULL;
	bool mfa = false;
	bool user_exists;
	char *on_behalf_of = NULL;

	err = set_global_tracing_level(TRACE);
	if (err != NULL) {
		printf("Failed setting the tracing level: %s\n", err->msg);
		goto OUT;
	}

	err = tpm_init(NULL, &tpm);
	if (err != NULL) {
		printf("Failed to initialize tpm: %s\n", err->msg);
		goto OUT;
	}
	auth_value_generate(&auth_value);
	printf("auth_value: %s\n", auth_value);

	err = tpm_machine_key_create(tpm, auth_value, &loadable_machine_key);
	if (err != NULL) {
		printf("Failed to create loadable machine key: %s\n", err->msg);
		goto OUT;
	}

	err = tpm_machine_key_load(tpm,
				   auth_value,
				   loadable_machine_key,
				   &machine_key);
	if (err != NULL) {
		printf("Failed to load machine key: %s\n", err->msg);
		goto OUT;
	}

	err = broker_init(NULL, NULL, NULL, NULL, &client);
	if (err != NULL) {
		printf("Failed to initialize the broker: %s\n", err->msg);
		goto OUT;
	}

	printf("Please enter your EntraID username: ");
	getline(&username, &len, stdin);
	strip_newline(username);

	domain = strchr(username, '@');
	if (domain != NULL) {
		domain++;
	} else {
		printf("Failed to find the domain name from the user upn: %s\n", err->msg);
		goto OUT;
	}

	err = broker_check_user_exists(client, username, &user_exists);
	if (err != NULL) {
		printf("Failed to check if the user exists: %s\n", err->msg);
		goto OUT;
	}
	if (user_exists) {
		printf("User %s exists!\n", username);
	} else {
		printf("User %s does not exist!\n", username);
		goto OUT;
	}

	password = getpass("Password: ");

	err = broker_initiate_acquire_token_by_mfa_flow_for_device_enrollment(client,
									      username,
									      password,
									      &flow);
	if (err != NULL) {
		printf("Failed to initiate an mfa token acquire: %s\n", err->msg);
		goto OUT;
	}

	err = mfa_auth_continue_msg(flow, &msg);
	if (err != NULL) {
		printf("Failed to fetch MFA auth message: %s\n", err->msg);
		goto OUT;
	}
	printf("%s", msg);
	fflush(stdout);

	err = mfa_auth_continue_mfa_method(flow, &mfa_method);
	if (err != NULL) {
		printf("Failed to fetch MFA method: %s\n", err->msg);
		goto OUT;
	}
	if (strcmp(mfa_method, "PhoneAppOTP") == 0
	 || strcmp(mfa_method, "OneWaySMS") == 0
	 || strcmp(mfa_method, "ConsolidatedTelephony") == 0) {
		char *otp = getpass("");
		err = broker_acquire_token_by_mfa_flow(client,
						       username,
						       otp,
						       0,
						       flow,
						       &token);
		if (err != NULL) {
			printf("Failed to authenticate with otp: %s\n", err->msg);
			goto OUT;
		}
	} else {
		printf("\n");
		int polling_interval = mfa_auth_continue_polling_interval(flow);
		int max_poll_attempts = mfa_auth_continue_max_poll_attempts(flow);
		for (int i = 0; i < max_poll_attempts; i++) {
			err = broker_acquire_token_by_mfa_flow(client,
							       username,
							       NULL,
							       i,
							       flow,
							       &token);
			if (err == NULL) {
			    break;
			} else if (err->code == MFA_POLL_CONTINUE) {
				sleep(polling_interval/1000);
			} else {
				printf("Failed to authenticate when polling: %s\n", err->msg);
				goto OUT;
			}
		}
	}
	printf("Authentication was successful!\n");

	err = enroll_attrs_init(domain,
				"msal_example_c",
				NULL,
				0,
				NULL,
				&attrs);
	if (err != NULL) {
		printf("Failed to create enrollment attributes: %s\n", err->msg);
		goto OUT;
	}

	err = user_token_refresh_token(token, &refresh_token);
	if (err != NULL) {
		printf("Failed fetching refresh token: %s\n", err->msg);
		goto OUT;
	}

	err = broker_enroll_device(client,
				   refresh_token,
				   attrs,
				   tpm,
				   machine_key,
				   &transport_key,
				   &cert_key,
				   &device_id);
	if (err != NULL) {
		printf("Failed to enroll the device: %s\n", err->msg);
		goto OUT;
	}
	printf("Enrolled with device id: %s\n", device_id);

	printf("Obtain PRT from enrollment refresh token\n");
	err = broker_acquire_token_by_refresh_token(client,
						    refresh_token,
						    NULL,
						    0,
						    NULL,
						    on_behalf_of,
						    tpm,
						    machine_key,
						    &token0);
	if (err != NULL) {
		printf("Failed to acquire token by refresh token: %s\n", err->msg);
		goto OUT;
	}

	err = user_token_access_token(token0, &access_token);
	if (err != NULL) {
		printf("Failed fetching access token: %s\n", err->msg);
		goto OUT;
	}
	err = user_token_spn(token0, &spn);
	if (err != NULL) {
		printf("Failed fetching token spn: %s\n", err->msg);
		goto OUT;
	}
	err = user_token_uuid(token0, &uuid);
	if (err != NULL) {
		printf("Failed fetching token uuid: %s\n", err->msg);
		goto OUT;
	}
	err = user_token_amr_mfa(token0, &mfa);
	if (err != NULL) {
		printf("Failed fetching token amr_mfa: %s\n", err->msg);
		goto OUT;
	}
	printf("access_token: %s, spn: %s, uuid: %s, mfa?: %d\n",
	       access_token,
	       spn,
	       uuid,
	       mfa);

	printf("Provision hello key");
	err = broker_provision_hello_for_business_key(client,
						      token,
						      tpm,
						      machine_key,
						      "123456",
						      &hello_key);
	if (err != NULL) {
		printf("Failed to provision a hello key: %s\n", err->msg);
		goto OUT;
	}

	printf("Acquire token via hello key\n");

	user_token_free(token0);
	err = broker_acquire_token_by_hello_for_business_key(client,
							     username,
							     hello_key,
							     NULL,
							     0,
							     NULL,
							     on_behalf_of,
							     tpm,
							     machine_key,
							     "123456",
							     &token0);
	if (err != NULL) {
		printf("Failed to acquire a token using the provisioned hello key: %s\n", err->msg);
		goto OUT;
	}

	string_free(access_token);
	err = user_token_access_token(token0, &access_token);
	if (err != NULL) {
		printf("Failed fetching access token: %s\n", err->msg);
		goto OUT;
	}
	string_free(spn);
	err = user_token_spn(token0, &spn);
	if (err != NULL) {
		printf("Failed fetching token spn: %s\n", err->msg);
		goto OUT;
	}
	string_free(uuid);
	err = user_token_uuid(token0, &uuid);
	if (err != NULL) {
		printf("Failed fetching token uuid: %s\n", err->msg);
		goto OUT;
	}
	err = user_token_amr_mfa(token0, &mfa);
	if (err != NULL) {
		printf("Failed fetching token amr_mfa: %s\n", err->msg);
		goto OUT;
	}
	printf("access_token: %s, spn: %s, uuid: %s, mfa?: %d\n",
	       access_token,
	       spn,
	       uuid,
	       mfa);

	printf("Unseal the TGT from the PRT\n");
	err = user_token_prt(token0, &prt);
	if (err != NULL) {
		printf("Failed fetching token prt: %s\n", err->msg);
		goto OUT;
	}

	printf("Parse the TGT into a Kerberos ccache\n");
	err = broker_store_cloud_tgt(client,
				     prt,
				     "./c_test_ccache",
				     tpm,
				     machine_key);
	if (err != NULL) {
		printf("Failed storing TGT: %s\n", err->msg);
		goto OUT;
	}
	cat_file("./c_test_ccache");

	printf("\nUnseal the Kerberos top level names\n");
	err = broker_unseal_prt_kerberos_top_level_names(client,
							 prt,
							 tpm,
							 machine_key,
							 &kerberos_top_level_names);
	if (err != NULL) {
		printf("Failed to unseal the kerberos top level names: %s\n", err->msg);
		goto OUT;
	}
	printf("%s\n", kerberos_top_level_names);

OUT:
    error_free(err);
	user_token_free(token);
	user_token_free(token0);
	mfa_auth_continue_free(flow);
	string_free(auth_value);
	loadable_machine_key_free(loadable_machine_key);
	machine_key_free(machine_key);
	broker_free(client);
	tpm_free(tpm);
	free(username);
	string_free(msg);
	string_free(mfa_method);
	string_free(device_id);
	loadable_ms_oapxbc_rsa_key_free(transport_key);
	loadable_ms_device_enrollment_key_free(cert_key);
	loadable_ms_hello_key_free(hello_key);
	sealed_data_free(prt);
	string_free(refresh_token);
	string_free(access_token);
	string_free(spn);
	string_free(uuid);
	string_free(kerberos_top_level_names);
}
