package admin

import (
	"fmt"
	"os"
)

// CredentialsFromEnv reads the administrator credentials the tools here take from the environment,
// never from a flag, so they stay out of shell history:
//
//   - KEYCLOAK_ADMIN_CLIENT_ID and KEYCLOAK_ADMIN_CLIENT_KEY_FILE, the path of the service account's
//     PEM private key, for a master-realm service account;
//   - KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD, the bootstrap administrator, for a throwaway
//     instance.
//
// A configured service account is never backed by the password. A key that fails to load is an
// error, not a quiet fall back to a password login.
func CredentialsFromEnv() (Credentials, error) {
	clientID := os.Getenv("KEYCLOAK_ADMIN_CLIENT_ID")
	if clientID == "" {
		return Credentials{Username: os.Getenv("KEYCLOAK_ADMIN_USER"), Password: os.Getenv("KEYCLOAK_ADMIN_PASSWORD")}, nil
	}
	path := os.Getenv("KEYCLOAK_ADMIN_CLIENT_KEY_FILE")
	if path == "" {
		return Credentials{}, fmt.Errorf("admin: KEYCLOAK_ADMIN_CLIENT_ID is %q but KEYCLOAK_ADMIN_CLIENT_KEY_FILE is unset", clientID)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("admin: reading the service account's key: %w", err)
	}
	key, err := ParseClientKey(raw)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{ClientID: clientID, ClientKey: &key}, nil
}
