/*
 * Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
 *
 * This source code is licensed under the Apache 2.0 license found
 * in the LICENSE file in the root directory of this source tree.
 */

package gost_crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ftomza/gogost/gost3410"
	"golang.org/x/crypto/cryptobyte"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidTc26Gost34102012256                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidTc26Gost34102012512                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	oidTc26Gost34112012256                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidTc26Gost34112012512                = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
	oidTc26signwithdigestgost341012256    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidTc26signwithdigestgost341012512    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidTc26agreementgost341012256         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 1}
	oidTc26agreementgost341012512         = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 2}
	oidTc26Gost34102012256Signature       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidTc26Gost34102012512Signature       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidGostR34102001CryptoProAParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
	oidGostR34102001CryptoProBParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
	oidGostR34102001CryptoProCParamSet    = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}
	oidGostR34102001CryptoProXchAParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	oidGostR34102001CryptoProXchBParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}
	oidTc26Gost34102012256ParamSetA       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	oidTc26Gost34102012256ParamSetB       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	oidTc26Gost34102012256ParamSetC       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	oidTc26Gost34102012256ParamSetD       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
	oidTc26Gost34102012512ParamSetA       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
	oidTc26Gost34102012512ParamSetB       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	oidTc26Gost34102012512ParamSetC       = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
	oidtc26gost341112256                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidtc26gost341112512                  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	GOST
)

var publicKeyAlgoName = [...]string{
	GOST: "GOST",
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKeyInfo      publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}

type GostR34102012PublicKeyParameters struct {
	PublicKeyParamSet asn1.ObjectIdentifier
	DigestParamSet    asn1.ObjectIdentifier `asn1:"optional"`
}

func ParseCertificate(derBytes []byte) ([]byte, error) {
	var cert certificate
	rest, err := asn1.Unmarshal(derBytes, &cert)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of certificate")
	}

	return cert.TBSCertificate.PublicKeyInfo.Raw, nil
}

func ParsePKIXPublicKey(derBytes []byte) (pub *gost3410.PublicKey, err error) {
	var pki publicKeyInfo
	pki, err = getPublicKeyInfo(derBytes)
	if err != nil {
		return nil, err
	}
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, fmt.Errorf("x509: unknown public key algorithm: %v", pki.Algorithm.Algorithm)
	}
	return parsePublicKey(algo, &pki)
}

func getPublicKeyInfo(derBytes []byte) (publicKeyInfo, error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return publicKeyInfo{}, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return publicKeyInfo{}, err
	} else if len(rest) != 0 {
		return publicKeyInfo{}, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	return pki, nil
}

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidTc26Gost34102012256):
		return GOST
	case oid.Equal(oidTc26Gost34102012512):
		return GOST
	case oid.Equal(oidTc26agreementgost341012256):
		return GOST
	case oid.Equal(oidTc26agreementgost341012512):
		return GOST
	case oid.Equal(oidTc26signwithdigestgost341012256):
		return GOST
	case oid.Equal(oidTc26signwithdigestgost341012512):
		return GOST
	}
	return UnknownPublicKeyAlgorithm
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (*gost3410.PublicKey, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case GOST:
		var pubRaw []byte
		s := cryptobyte.String(asn1Data)
		if !s.ReadASN1Bytes(&pubRaw, cryptobyte_asn1.OCTET_STRING) {
			return nil, errors.New("x509: can not decode GOST public key")
		}
		curve, err := getCurve(keyData.Algorithm)
		if err != nil {
			return nil, err
		}
		return gost3410.NewPublicKey(curve, pubRaw)
	default:
		return nil, nil
	}
}

func getCurve(algoData pkix.AlgorithmIdentifier) (*gost3410.Curve, error) {
	paramsData := algoData.Parameters.FullBytes
	var publicKeyParams GostR34102012PublicKeyParameters
	rest, err := asn1.Unmarshal(paramsData, &publicKeyParams)
	if err != nil {
		return nil, errors.New("x509: failed to parse GOST parameters")
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after GOST parameters")
	}
	var curve *gost3410.Curve
	switch {
	case publicKeyParams.PublicKeyParamSet.Equal(oidGostR34102001CryptoProAParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
	case publicKeyParams.PublicKeyParamSet.Equal(oidGostR34102001CryptoProBParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
	case publicKeyParams.PublicKeyParamSet.Equal(oidGostR34102001CryptoProCParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
	case publicKeyParams.PublicKeyParamSet.Equal(oidGostR34102001CryptoProXchAParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
	case publicKeyParams.PublicKeyParamSet.Equal(oidGostR34102001CryptoProXchBParamSet):
		curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012256ParamSetA):
		curve = gost3410.CurveIdtc26gost34102012256paramSetA()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012256ParamSetB):
		curve = gost3410.CurveIdtc26gost34102012256paramSetB()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012256ParamSetC):
		curve = gost3410.CurveIdtc26gost34102012256paramSetC()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012256ParamSetD):
		curve = gost3410.CurveIdtc26gost34102012256paramSetD()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012512ParamSetA):
		curve = gost3410.CurveIdtc26gost341012512paramSetA()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012512ParamSetB):
		curve = gost3410.CurveIdtc26gost341012512paramSetB()
	case publicKeyParams.PublicKeyParamSet.Equal(oidTc26Gost34102012512ParamSetC):
		curve = gost3410.CurveIdtc26gost34102012512paramSetC()
	default:
		return nil, errors.New("x509: unknown GOST curve")
	}
	return curve, nil
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

func ParsePKCS8PrivateKey(derBytes []byte) (key *gost3410.PrivateKey, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(derBytes, &privKey); err != nil {
		return nil, err
	}
	algo := getPublicKeyAlgorithmFromOID(privKey.Algo.Algorithm)
	switch algo {
	case GOST:
		var privRaw []byte
		s := cryptobyte.String(privKey.PrivateKey)
		if !s.ReadASN1Bytes(&privRaw, cryptobyte_asn1.OCTET_STRING) {
			return nil, errors.New("x509: can not decode GOST public key")
		}
		curve, err := getCurve(privKey.Algo)
		if err != nil {
			return nil, err
		}
		return gost3410.NewPrivateKey(curve, privRaw)
	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

func DerDecode(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("DER: content not found")
	}

	return block, nil
}
