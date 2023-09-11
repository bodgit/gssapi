package gssapi

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

const (
	krb5FilePrefix   = "FILE:"
	krb5Config       = "KRB5_CONFIG"
	krb5CCName       = "KRB5CCNAME"
	krb5KTName       = "KRB5_KTNAME"
	krb5ClientKTName = "KRB5_CLIENT_KTNAME"
)

func findFile(env string, try []string) (string, error) {
	path, ok := os.LookupEnv(env)
	if ok {
		path = strings.TrimPrefix(path, krb5FilePrefix)

		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("%s: %w", env, err)
		}

		return path, nil
	}

	errs := fmt.Errorf("%s: not found", env)

	for _, t := range try {
		if _, err := os.Stat(t); err != nil {
			errs = multierror.Append(errs, err)

			if os.IsNotExist(err) {
				continue
			}

			return "", errs
		}

		return t, nil
	}

	return "", errs
}

func loadConfig() (*config.Config, error) {
	path, err := findFile(krb5Config, []string{"/etc/krb5.conf"})
	if err != nil {
		return nil, err
	}

	return config.Load(path)
}

func loadCCache() (*credentials.CCache, error) {
	path, err := findFile(krb5CCName, []string{fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())})
	if err != nil {
		return nil, err
	}

	return credentials.LoadCCache(path)
}

func loadKeytab() (*keytab.Keytab, error) {
	path, err := findFile(krb5KTName, []string{"/etc/krb5.keytab"})
	if err != nil {
		return nil, err
	}

	return keytab.Load(path)
}

func loadClientKeytab() (*keytab.Keytab, error) {
	//nolint:lll
	path, err := findFile(krb5ClientKTName, []string{fmt.Sprintf("/var/kerberos/krb5/user/%d/client.keytab", os.Geteuid())})
	if err != nil {
		return nil, err
	}

	return keytab.Load(path)
}
