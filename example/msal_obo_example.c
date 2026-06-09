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

/*
 * OBO (On-Behalf-Of) flow example using ConfidentialClientApplication.
 *
 * This demonstrates acquiring a token for a downstream API on behalf of
 * a user whose access token you already possess (the "user assertion").
 *
 * Usage:
 *   gcc -g msal_obo_example.c -lhimmelblau ${LDFLAGS} ${CFLAGS} -DON_BEHALF_OF
 *   ./a.out
 *
 * You will be prompted for:
 *   - Client ID (the confidential app registration)
 *   - Client secret
 *   - Authority (e.g. https://login.microsoftonline.com/<tenant>)
 *   - User assertion (the incoming access token)
 *   - Scopes for the downstream API
 */

#include <stdio.h>
#include <himmelblau/himmelblau.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

void strip_newline(char *str) {
	int len = strlen(str);
	if (len > 0 && str[len - 1] == '\n') {
		str[len - 1] = '\0';
	}
}

int main() {
	ConfidentialClientApplication *app = NULL;
	OboToken *obo_token = NULL;
	MSAL_ERROR *err = NULL;
	int rc = 0;
	char *client_id = NULL;
	char *client_secret = NULL;
	char *authority = NULL;
	char *user_assertion = NULL;
	char *scope = NULL;
	char *access_token = NULL;
	char *refresh_token = NULL;
	char *token_scope = NULL;
	char *token_type = NULL;
	uint32_t expires_in = 0;
	uint32_t ext_expires_in = 0;
	size_t len = 0;

	err = set_global_tracing_level(DEBUG);
	if (err != NULL) {
		printf("Failed setting the tracing level: %s\n", err->msg);
		rc = 1; goto OUT;
	}

	/* Collect configuration */
	printf("Client ID: ");
	getline(&client_id, &len, stdin);
	strip_newline(client_id);

	printf("Client secret: ");
	getline(&client_secret, &len, stdin);
	strip_newline(client_secret);

	printf("Authority (e.g. https://login.microsoftonline.com/<tenant>): ");
	getline(&authority, &len, stdin);
	strip_newline(authority);

	printf("User assertion (the incoming access token): ");
	getline(&user_assertion, &len, stdin);
	strip_newline(user_assertion);

	printf("Downstream scope (e.g. https://graph.microsoft.com/.default): ");
	getline(&scope, &len, stdin);
	strip_newline(scope);

	/* Initialize the confidential client */
	err = confidential_client_init_with_secret(
		client_id,
		authority,
		client_secret,
		&app);
	if (err != NULL) {
		printf("Failed to initialize confidential client: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	printf("Confidential client initialized.\n");

	/* Perform the OBO exchange */
	const char *scopes[] = { scope };
	err = confidential_acquire_token_on_behalf_of(
		app,
		user_assertion,
		scopes,
		1,
		&obo_token);
	if (err != NULL) {
		printf("OBO token acquisition failed: %s\n", err->msg);
		if (err->code == OBO_INTERACTION_REQUIRED) {
			printf("  -> Conditional Access requires user interaction.\n");
			printf("  -> Propagate the claims challenge back to the caller.\n");
			if (err->claims != NULL) {
				printf("  -> claims: %s\n", err->claims);
			}
		}
		rc = 1; goto OUT;
	}

	/* Display the acquired token */
	err = obo_token_access_token(obo_token, &access_token);
	if (err != NULL) {
		printf("Failed fetching access token: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	printf("OBO access token: %s\n", access_token);

	err = obo_token_token_type(obo_token, &token_type);
	if (err != NULL) {
		printf("Failed fetching token type: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	printf("Token type: %s\n", token_type);

	err = obo_token_expires_in(obo_token, &expires_in);
	if (err != NULL) {
		printf("Failed fetching expires_in: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	printf("Expires in: %u\n", expires_in);

	err = obo_token_ext_expires_in(obo_token, &ext_expires_in);
	if (err != NULL) {
		printf("Failed fetching ext_expires_in: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	printf("Ext expires in: %u\n", ext_expires_in);

	err = obo_token_scope(obo_token, &token_scope);
	if (err != NULL) {
		printf("Failed fetching scope: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	if (token_scope != NULL) {
		printf("Scope:        %s\n", token_scope);
	} else {
		printf("Scope:        (not returned)\n");
	}

	err = obo_token_refresh_token(obo_token, &refresh_token);
	if (err != NULL) {
		printf("Failed fetching refresh token: %s\n", err->msg);
		rc = 1; goto OUT;
	}
	if (refresh_token != NULL) {
		printf("Refresh token: (present)\n");
	} else {
		printf("Refresh token: (not returned -- request offline_access scope)\n");
	}

	printf("\nOBO exchange completed successfully!\n");

OUT:
	error_free(err);
	obo_token_free(obo_token);
	confidential_client_free(app);
	free(client_id);
	free(client_secret);
	free(authority);
	free(user_assertion);
	free(scope);
	string_free(access_token);
	string_free(refresh_token);
	string_free(token_scope);
	string_free(token_type);
	return rc;
}
