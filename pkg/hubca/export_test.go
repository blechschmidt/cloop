package hubca

import (
	"crypto/ecdsa"
	"errors"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// OpenStagedKeyForTest opens the staged CA's private key, for a test that
// signs with it the way an attacker holding it could.
func OpenStagedKeyForTest(s *Store, sealer Sealer, serial string) (*ecdsa.PrivateKey, error) {
	row, err := s.db.GetHubTLS(statedb.HubCANext)
	if err != nil {
		return nil, err
	}
	if row.Serial != serial {
		return nil, errors.New("hubca: that CA is not the staged one")
	}
	cert, err := ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, err
	}
	key, err := openKey(sealer, row, cert)
	if err != nil {
		return nil, err
	}
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("hubca: not an ECDSA key")
	}
	return k, nil
}
