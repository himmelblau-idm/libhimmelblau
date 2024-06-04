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

void strip_newline(char *str) {
	int len = strlen(str);
	if (str[len-1] == '\n') {
		str[len-1] = '\0';
	}
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
	LoadableIdentityKey *cert_key = NULL;
	LoadableIdentityKey *hello_key = NULL;
	MSAL_ERROR err;
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
	bool mfa = false;
	bool user_exists;

	err = set_global_tracing_level(TRACE);
	if (err != SUCCESS) {
		printf("Failed setting the tracing level\n");
		goto OUT;
	}

	err = tpm_init(NULL, &tpm);
	if (err != SUCCESS) {
		printf("Failed to initialize tpm!\n");
		goto OUT;
	}
	auth_value_generate(&auth_value);
	printf("auth_value: %s\n", auth_value);

	err = tpm_machine_key_create(tpm, auth_value, &loadable_machine_key);
	if (err != SUCCESS) {
		printf("Failed to create loadable machine key!\n");
		goto OUT;
	}

	err = tpm_machine_key_load(tpm,
				   auth_value,
				   loadable_machine_key,
				   &machine_key);
	if (err != SUCCESS) {
		printf("Failed to load machine key!\n");
		goto OUT;
	}

	err = broker_init(NULL, NULL, NULL, &client);
	if (err != SUCCESS) {
		printf("Failed to initialize the broker!\n");
		goto OUT;
	}

	printf("Please enter your EntraID username: ");
	getline(&username, &len, stdin);
	strip_newline(username);

	domain = strchr(username, '@');
	if (domain != NULL) {
		domain++;
	} else {
		printf("Failed to find the domain name from the user upn!\n");
		goto OUT;
	}

	err = broker_check_user_exists(client, username, &user_exists);
	if (err != SUCCESS) {
		printf("Failed to check if the user exists!\n");
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
	if (err != SUCCESS) {
		printf("Failed to initiate an mfa token acquire!\n");
		goto OUT;
	}

	err = mfa_auth_continue_msg(flow, &msg);
	if (err != SUCCESS) {
		printf("Failed to fetch MFA auth message!\n");
		goto OUT;
	}
	printf("%s", msg);
	fflush(stdout);

	err = mfa_auth_continue_mfa_method(flow, &mfa_method);
	if (err != SUCCESS) {
		printf("Failed to fetch MFA method!\n");
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
		if (err != SUCCESS) {
			printf("Failed to authenticate with otp!\n");
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
			if (err == MFA_POLL_CONTINUE) {
				sleep(polling_interval/1000);
			} else if (err == SUCCESS) {
				break;
			} else {
				printf("Failed to authenticate when polling!\n");
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
	if (err != SUCCESS) {
		printf("Failed to create enrollment attributes!\n");
		goto OUT;
	}

	err = broker_enroll_device(client,
				   token,
				   attrs,
				   tpm,
				   machine_key,
				   &transport_key,
				   &cert_key,
				   &device_id);
	if (err != SUCCESS) {
		printf("Failed to enroll the device!\n");
		goto OUT;
	}
	printf("Enrolled with device id: %s\n", device_id);

	printf("Obtain PRT from enrollment refresh token\n");
	err = user_token_refresh_token(token, &refresh_token);
	if (err != SUCCESS) {
		printf("Failed fetching refresh token\n");
		goto OUT;
	}
	err = broker_acquire_token_by_refresh_token(client,
						    refresh_token,
						    NULL,
						    0,
						    NULL,
						    tpm,
						    machine_key,
						    &token0);
	if (err != SUCCESS) {
		printf("Failed to acquire token by refresh token\n");
		goto OUT;
	}

	err = user_token_access_token(token0, &access_token);
	if (err != SUCCESS) {
		printf("Failed fetching access token\n");
		goto OUT;
	}
	err = user_token_spn(token0, &spn);
	if (err != SUCCESS) {
		printf("Failed fetching token spn\n");
		goto OUT;
	}
	err = user_token_uuid(token0, &uuid);
	if (err != SUCCESS) {
		printf("Failed fetching token uuid\n");
		goto OUT;
	}
	err = user_token_amr_mfa(token0, &mfa);
	if (err != SUCCESS) {
		printf("Failed fetching token amr_mfa\n");
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
	if (err != SUCCESS) {
		printf("Failed to provision a hello key!\n");
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
							     tpm,
							     machine_key,
							     "123456",
							     &token0);
	if (err != SUCCESS) {
		printf("Failed to aquire a token using the provisioned hello key!\n");
		goto OUT;
	}

	string_free(access_token);
	err = user_token_access_token(token0, &access_token);
	if (err != SUCCESS) {
		printf("Failed fetching access token\n");
		goto OUT;
	}
	string_free(spn);
	err = user_token_spn(token0, &spn);
	if (err != SUCCESS) {
		printf("Failed fetching token spn\n");
		goto OUT;
	}
	string_free(uuid);
	err = user_token_uuid(token0, &uuid);
	if (err != SUCCESS) {
		printf("Failed fetching token uuid\n");
		goto OUT;
	}
	err = user_token_amr_mfa(token0, &mfa);
	if (err != SUCCESS) {
		printf("Failed fetching token amr_mfa\n");
		goto OUT;
	}
	printf("access_token: %s, spn: %s, uuid: %s, mfa?: %d\n",
	       access_token,
	       spn,
	       uuid,
	       mfa);

OUT:
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
	loadable_identity_key_free(cert_key);
	loadable_identity_key_free(hello_key);
	string_free(refresh_token);
	string_free(access_token);
	string_free(spn);
	string_free(uuid);
}
