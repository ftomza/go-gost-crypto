/*
 * Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
 *
 * This source code is licensed under the Apache 2.0 license found
 * in the LICENSE file in the root directory of this source tree.
 */

package gost_crypto_test

import (
	"math/big"
	"reflect"
	"testing"

	gost_crypto "github.com/ftomza/go-gost-crypto"

	"github.com/ftomza/gogost/gost3410"
)

var (
	priv = []byte(`
-----BEGIN PRIVATE KEY-----
MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgAnLfE4VXwFTuD5HbBX84W9f/NLDcxNXUWHB+Atu/
6BE=
-----END PRIVATE KEY-----
`)
	pub = []byte(`
-----BEGIN CERTIFICATE-----
MIIEfDCCBCmgAwIBAgIEXek0LjAKBggqhQMHAQEDAjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q
n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G
A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7
MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wHhcNMjAwOTIyMjEw
MDAwWhcNNDAwOTIyMjEwMDAwWjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C10YLQtdGA0LHR
g9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UECwwW0KDRg9C6
0L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0JDQ
u9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wZjAfBggqhQMHAQEBATATBgcqhQMCAiQA
BggqhQMHAQECAgNDAARAyuHXvOdPT/R94KICw82bdgiBfEXkEJxqXIN4uav8zIvgDe/q7yzK+HJnbLWLIWc2z+eqbaiUbj0Y
e1RoNUa5NaOCAZ4wggGaMA4GA1UdDwEB/wQEAwIB/jAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMD
BggrBgEFBQcDBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSalTlfa+t/MpLv76stCkVlU18TazCCASMGA1UdIwSCARow
ggEWgBSalTlfa+t/MpLv76stCkVlU18Ta6GB96SB9DCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q
n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G
A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7
MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L2CBF3pNC4wCgYIKoUD
BwEBAwIDQQBlY4HdS/G7zAWOEWH6pBx4FSli5ipbEtvr/lkjEApvlrch5cMlmy7rglAbE7ct+sKFtDKv6cIhqu3rQMAla/gb
-----END CERTIFICATE-----
`)
)

func getBigInt(t *testing.T, in string) *big.Int {
	v, ok := new(big.Int).SetString(in, 10)
	if !ok {
		t.Fatal("cannot convert string to bigInt")
	}
	return v
}

func getDer(t *testing.T, data []byte) []byte {
	block, err := gost_crypto.DerDecode(data)
	if err != nil {
		t.Fatal(err)
	}
	return block.Bytes
}

func getPublicKeyData(t *testing.T, data []byte) []byte {
	der, err := gost_crypto.ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParsePKCS8PrivateKey(t *testing.T) {
	type args struct {
		der []byte
	}

	tests := []struct {
		name    string
		args    args
		wantKey *gost3410.PrivateKey
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				der: getDer(t, priv),
			},
			wantKey: &gost3410.PrivateKey{
				C:   gost3410.CurveIdGostR34102001CryptoProXchAParamSet(),
				Key: getBigInt(t, "8100551082987309382040692774861374330127499061554316741502830866978492609026"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := gost_crypto.ParsePKCS8PrivateKey(tt.args.der)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePKCS8PrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("ParsePKCS8PrivateKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		wantPub *gost3410.PublicKey
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				derBytes: getPublicKeyData(t, getDer(t, pub)),
			},
			wantPub: &gost3410.PublicKey{
				C: gost3410.CurveIdGostR34102001CryptoProXchAParamSet(),
				X: getBigInt(t, "63233666624051439876354823295566418637012564188384438200469674371110357426634"),
				Y: getBigInt(t, "24299932244005800117978005500793438667981994951685184390218551551204573253088"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPub, err := gost_crypto.ParsePKIXPublicKey(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePKIXPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPub, tt.wantPub) {
				t.Errorf("ParsePKIXPublicKey() gotPub = %v, want %v", gotPub, tt.wantPub)
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				getDer(t, pub),
			},
			want:    []byte{48, 102, 48, 31, 6, 8, 42, 133, 3, 7, 1, 1, 1, 1, 48, 19, 6, 7, 42, 133, 3, 2, 2, 36, 0, 6, 8, 42, 133, 3, 7, 1, 1, 2, 2, 3, 67, 0, 4, 64, 202, 225, 215, 188, 231, 79, 79, 244, 125, 224, 162, 2, 195, 205, 155, 118, 8, 129, 124, 69, 228, 16, 156, 106, 92, 131, 120, 185, 171, 252, 204, 139, 224, 13, 239, 234, 239, 44, 202, 248, 114, 103, 108, 181, 139, 33, 103, 54, 207, 231, 170, 109, 168, 148, 110, 61, 24, 123, 84, 104, 53, 70, 185, 53},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gost_crypto.ParseCertificate(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
