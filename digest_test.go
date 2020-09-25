/*
 * Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
 *
 * This source code is licensed under the Apache 2.0 license found
 * in the LICENSE file in the root directory of this source tree.
 */

package gost_crypto_test

import (
	"go-gost-crypto"
	"hash"
	"reflect"
	"testing"

	"github.com/ftomza/gogost/gost34112012256"
)

func TestParsePKIXPublicKeyHash(t *testing.T) {
	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name     string
		args     args
		wantHash hash.Hash
		wantErr  bool
	}{
		{
			name:     "ok",
			args:     args{getPublicKeyData(t, getDer(t, pub))},
			wantHash: gost34112012256.New(),
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHash, err := gost_crypto.ParsePKIXPublicKeyHash(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePKIXPublicKeyHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotHash, tt.wantHash) {
				t.Errorf("ParsePKIXPublicKeyHash() gotHash = %v, want %v", gotHash, tt.wantHash)
			}
		})
	}
}
