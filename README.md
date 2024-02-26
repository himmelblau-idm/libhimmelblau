MSAL
====

The purpose of this project is to implement MSAL for Rust, based on the specifications found in the Microsoft API Reference for [ClientApplication Class](https://learn.microsoft.com/en-us/python/api/msal/msal.application.clientapplication?view=msal-py-latest) and [PublicClientApplication Class](https://learn.microsoft.com/en-us/python/api/msal/msal.application.publicclientapplication?view=msal-py-latest). These are Python references which will be mimicked in Rust here.

> **_NOTE:_**  Implementing the [ConfidentialClientApplication Class](https://learn.microsoft.com/en-us/python/api/msal/msal.application.confidentialclientapplication?view=msal-py-latest) is not currently a target for this project. If you are interested in volunteering to implement the ConfidentialClientApplication Class, please contact the maintainer.

The project also implements the [MS-DRS] protocol, which is undocumented by
microsoft. A [protocol specification](https://github.com/himmelblau-idm/aad-join-spec/releases/latest)
is in progress as part of the himmelblau project.

In addition to the ClientApplication Class and [MS-DRS] implementations, this project implements [MS-OAPXBC] sections [3.1.5.1.2 Request for Primary Refresh Token](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/d32d5cd0-05d4-4ec2-8bcc-ac29ce711c23) and [3.1.5.1.3 Exchange Primary Refresh Token for Access Token](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/06e2bf0d-8cea-4b11-ad78-d212330ebda9). These are not implemented in Microsoft's MSAL libraries, but are possible when authenticating from an enrolled device.

How do I use this library?
--------------------------

Import the module into your project, then include the PublicClientApplication:

```Rust
use msal::PublicClientApplication;
```

Create an instance of the PublicClientApplication, then authenticate:

```Rust
let authority = format!("https://login.microsoftonline.com/{}", tenant_id);
let app = PublicClientApplication::new(client_id, Some(&authority)).expect("Failed creating app");
let scope = vec![];
let token = app.acquire_token_by_username_password(username, password, scope).await?;
```

You can obtain your `client_id` and `tenant_id` from the Azure portal.

You can perform a silent auth using a previously obtained refresh token:

```Rust
let token = app.acquire_token_silent(scope, &token.refresh_token).await?;
```

Or finally, you can perform a Device Authorization Grant:

```Rust
let flow = app.initiate_device_flow(scope).await?;

// Prompt the user with the message found in flow.message

let token = app.acquire_token_by_device_flow(flow).await?;
```

If msal is built with the `broker` feature, you can enroll the device, then request an authentication token:

```Rust
use kanidm_hsm_crypto::soft::SoftTpm;
use kanidm_hsm_crypto::{BoxedDynTpm, Tpm, AuthValue};

// First create the TPM object and a machine_key
let mut tpm = BoxedDynTpm::new(SoftTpm::new());
let auth_str = AuthValue::generate().expect("Failed to create hex pin");
let auth_value = AuthValue::from_str(&auth_str).expect("Unable to create auth value");
let loadable_machine_key = tpm
    .machine_key_create(&auth_value)
    .expect("Unable to create new machine key");
let machine_key = tpm
    .machine_key_load(&auth_value, &loadable_machine_key)
    .expect("Unable to load machine key");

let app = BrokerClientApplication::new(Some(&authority), None, None).expect("Failed creating app");

// Obtain a token for authentication. If authenticating here without MFA, the PRT and
// user token will not have the mfa claim. Use initiate_device_flow_for_device_enrollment()
// and acquire_token_by_device_flow() to authenticate with the
// mfa claim.
let token = app.acquire_token_by_username_password_for_device_enrollment(username, password).await?;
// Specify the attributes which will be used for enrollment
let attrs = match EnrollAttrs::new(
    domain.to_string(),
    Some("test_machine".to_string()), // Device name
    Some("Linux".to_string()), // Device type
    Some(0), // Join type
    Some("openSUSE Leap 15.5".to_string()), // OS version
) {
    Ok(attrs) => attrs,
    Err(e) => {
        println!("{:?}", e);
        return ();
    }
};
// Use the tpm for enrollment.
let (transport_key, cert_key, device_id) = app.enroll_device(&token, attrs, &mut tpm, &machine_key).await?;

// Request an authentication token
let token = app.acquire_token_by_username_password(username, password, scope, &mut tpm, &machine_key).await?;
```

In order to initialize a BrokerClientApplication that was previously enrolled, ensure you've cached your `auth_value`, `loadable_machine_key`, `transport_key`, and `cert_key`. The `auth_value` MUST be stored in a secure manor only accessible to your application. Preferably your application should execute as a unique user, and only that user will have read access to the `auth_value`. Re-initialize as follows:

```Rust
let mut tpm = BoxedDynTpm::new(SoftTpm::new());
let loadable_machine_key = tpm
    .machine_key_create(&auth_value)
    .expect("Unable to create new machine key");
let machine_key = tpm
    .machine_key_load(&auth_value, &loadable_machine_key)
    .expect("Unable to load machine key");

let app = BrokerClientApplication::new(Some(&authority), Some(&transport_key), Some(&cert_key)).expect("Failed creating app");
```
