# LDAP connector
> LDAP connector is a plug-in designed to support login via LDAP or Active Directory, including LDAPS and StartTLS.

## How to use

### Build
```bash
./answer build --with github.com/apache/answer-plugins/connector-ldap
```

### Configuration
- `Name` - Display name for the connector shown on the login page
- `Server` - LDAP server URL, e.g. `ldaps://ldap.example.com:636` or `ldap://ldap.example.com:389`
- `Base DN` - Base DN to search for users, e.g. `dc=example,dc=com`
- `Bind DN` - DN of the service account used to bind and search the directory
- `Bind Password` - Password for the bind DN
- `User Attribute` - LDAP attribute holding the username, e.g. `uid` for OpenLDAP or `sAMAccountName` for Active Directory
- `TLS CA Certificate Path` - Optional path to a custom CA certificate, used to verify the LDAP server's certificate (e.g. for a private/internal CA)

If the server URL starts with `ldaps://`, the connection is established over TLS directly. Otherwise, a plain connection is opened and upgraded via StartTLS.

Users must have a `mail` attribute set in LDAP, since it is required to create/match the Answer account on login.
