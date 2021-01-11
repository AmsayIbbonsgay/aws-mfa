
## Summary

This tool is designed to help you work around AWS's nonexistent mfa implementation for aws-cli. 

It does this by rewriting your AWS config and credentials files, so that the changes persist between terminal shells.


## Installation

---

## Usage

Usage is in the format:

```
mfa [profile] <mfa-code>
```

Where `<mfa-code>` is a 6 digit mfa code, likely from your mobile device or password manager.

If profile is not supplied, `default` profile is used. 

The script then:
1. Looks in your AWS config and credential files for the profile
2. Uses the credentials for that profile, along with your mfa code, to call to AWS STS to create temporary credentials that are authenticated with MFA
3. If the profile you're creating credentials for hasn't had temporary credentials generated before:
   * The credentials and config for your profile are copied to a new profile, `mfa-{profile}`
   * The temporary credentials are written to the original profile
 * Else, if the profile has been used before:
   *  The `mfa-{profile}` profile is used to generate credentials
   *  these credentials are written to `{profile}`