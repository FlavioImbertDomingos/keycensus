# Active Directory / AD CS: least privilege for keycensus

The `adcs` collector reads the forest's Public Key Services container over LDAP, which any
authenticated account can do. Give it an account that can do nothing else.

## The LDAP account

- [ ] A dedicated account (for example `svc-keycensus`), or a group Managed Service Account if keycensus
      runs on a domain-joined Windows host.
- [ ] Member of *Domain Users* only. No other groups, no delegated rights.
- [ ] *Account is sensitive and cannot be delegated* set.
- [ ] *Deny log on locally* and *Deny log on through Remote Desktop Services* applied through GPO.
- [ ] A long random password, stored in a secret store and referenced with `password_vault`,
      `password_aws_secret` or `password_azure_secret`, rotated on your normal schedule. Or use
      `auth: kerberos` with a keytab and no password in keycensus at all.
- [ ] `ldaps://` (or `start_tls: true`) with `verify_tls` pointing at your root CA. keycensus refuses a
      simple bind over plain LDAP.
- [ ] Optional: a fine-grained password policy for the account and an alert on its interactive logons.

## The CA database export

The `certutil -view` export runs **on each CA**, as a scheduled task:

- [ ] Run it as a dedicated account that holds only the CA's *Read* permission (CA properties >
      Security). It does not need *Issue and Manage Certificates* or *Manage CA*.
- [ ] Write the CSV to a share or bucket keycensus can read, not the other way round: keycensus never
      needs credentials on the CA.
- [ ] The export contains certificates and requester names, not private keys. Protect it like the
      CBOM: it is a list of every certificate the CA issued.
