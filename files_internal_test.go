package gssapi

import (
	"errors"
	iofs "io/fs"
	"os"
	"testing"

	"github.com/go-logr/logr/testr"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

const findFileEnvironment = "FIND_FILE"

var errStatError = errors.New("stat error")

type statErrorFs struct {
	afero.Fs
}

func (statErrorFs) Stat(_ string) (os.FileInfo, error) {
	return nil, errStatError
}

//nolint:funlen,paralleltest
func TestFindFile(t *testing.T) {
	tables := []struct {
		name   string
		fs     afero.Fs
		files  []string
		env    string
		try    []string
		result string
		err    error
	}{
		{
			"goodenv",
			afero.NewMemMapFs(),
			[]string{"/foo"},
			"/foo",
			[]string{},
			"/foo",
			nil,
		},
		{
			"first",
			afero.NewMemMapFs(),
			[]string{"/foo"},
			"",
			[]string{"/foo", "/bar"},
			"/foo",
			nil,
		},
		{
			"second",
			afero.NewMemMapFs(),
			[]string{"/bar"},
			"",
			[]string{"/foo", "/bar"},
			"/bar",
			nil,
		},
		{
			"badenv",
			afero.NewMemMapFs(),
			[]string{"/bar"},
			"/foo",
			[]string{},
			"",
			iofs.ErrNotExist,
		},
		{
			"badstat",
			statErrorFs{afero.NewMemMapFs()},
			[]string{"/foo"},
			"",
			[]string{"/foo"},
			"",
			errStatError,
		},
		{
			"none",
			afero.NewMemMapFs(),
			[]string{},
			"",
			[]string{"/foo"},
			"",
			iofs.ErrNotExist,
		},
	}

	//nolint:paralleltest
	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			oldFs := fs
			defer func() { fs = oldFs }()

			fs = table.fs

			for _, file := range table.files {
				if err := afero.WriteFile(fs, file, nil, 0); err != nil {
					t.Fatal(err)
				}
			}

			if table.env != "" {
				t.Setenv(findFileEnvironment, table.env)
			}

			result, err := findFile(testr.New(t), findFileEnvironment, table.try)

			assert.Equal(t, table.result, result)
			assert.ErrorIs(t, err, table.err)
		})
	}
}

//nolint:paralleltest
func TestLoadConfig(t *testing.T) {
	oldFs := fs
	defer func() { fs = oldFs }()

	fs = statErrorFs{afero.NewMemMapFs()}

	_, err := loadConfig(testr.New(t))

	assert.ErrorIs(t, err, errStatError)
}

//nolint:paralleltest
func TestLoadCCache(t *testing.T) {
	oldFs := fs
	defer func() { fs = oldFs }()

	fs = statErrorFs{afero.NewMemMapFs()}

	_, err := loadCCache(testr.New(t))

	assert.ErrorIs(t, err, errStatError)
}

//nolint:paralleltest
func TestLoadKeytab(t *testing.T) {
	oldFs := fs
	defer func() { fs = oldFs }()

	fs = statErrorFs{afero.NewMemMapFs()}

	_, err := loadKeytab(testr.New(t))

	assert.ErrorIs(t, err, errStatError)
}

//nolint:paralleltest
func TestLoadClientKeytab(t *testing.T) {
	oldFs := fs
	defer func() { fs = oldFs }()

	fs = statErrorFs{afero.NewMemMapFs()}

	_, err := loadClientKeytab(testr.New(t))

	assert.ErrorIs(t, err, errStatError)
}
