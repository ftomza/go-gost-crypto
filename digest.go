/*
 * Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
 *
 * This source code is licensed under the Apache 2.0 license found
 * in the LICENSE file in the root directory of this source tree.
 */
package gost_crypto

import (
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/ftomza/gogost/gost34112012256"
	"github.com/ftomza/gogost/gost34112012512"
)

type algorithmParam struct {
	Curve  asn1.ObjectIdentifier
	Digest asn1.ObjectIdentifier
}

func ParsePKIXPublicKeyHash(derBytes []byte) (hash hash.Hash, err error) {
	pki, err := getPublicKeyInfo(derBytes)
	if err != nil {
		return nil, err
	}

	var params algorithmParam
	rest, err := asn1.Unmarshal(pki.Algorithm.Parameters.FullBytes, &params)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of Algorithm Parameters")
	}

	switch {
	case params.Digest.Equal(oidtc26gost341112256):
		hash = gost34112012256.New()
	case params.Digest.Equal(oidtc26gost341112512):
		hash = gost34112012512.New()
	default:
		return nil, errors.New("x509: unknown algorithm")
	}

	return
}
