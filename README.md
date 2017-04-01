# Passwordless Authentication Provider for Vapor

Adds Passwordless Authentication support to the Vapor web framework.

## Usage

```swift
import Vapor
import Passwordless

let drop = Droplet()
try drop.addProvider(Passwordless.Provider.self)
```

## Config

To build, create a `passwordless.json` file in the `Config/secrets` folder.
You may need to create the `secrets` folder if it does not exist. The secrets
folder is under the gitignore and shouldn't be committed.

Here's an example `Config/secrets/passwordless.json`

```json
{
    "subject": "email",
    "same-device": true,
    "use-cookie": true,
    "signer": "hmac256",
    "key": passwordpasswordpasswordpassword
}
```
