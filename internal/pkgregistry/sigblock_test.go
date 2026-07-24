package pkgregistry

import (
	"errors"
	"testing"
)

func TestParseSignatureBlock_Valid(t *testing.T) {
	data := `{
		"format": 1,
		"signatures": [
			{"role":"developer","alg":"ed25519","key_id":"sha256:aaa","key":"cHVicw==","sig":"c2ln"},
			{"role":"oem-app","alg":"ed25519","key_id":"sha256:bbb","sig":"c2ln"}
		]
	}`
	sb, err := ParseSignatureBlock([]byte(data))
	if err != nil {
		t.Fatalf("ParseSignatureBlock: %v", err)
	}
	if len(sb.Signatures) != 2 || sb.Signatures[0].Role != RoleDeveloper {
		t.Fatalf("got %+v", sb)
	}
}

func TestParseSignatureBlock_Rejections(t *testing.T) {
	cases := []struct {
		name string
		data string
		want error
	}{
		{"bad format", `{"format":2,"signatures":[{"role":"developer","alg":"ed25519","key_id":"k","key":"a","sig":"s"}]}`, ErrSigBlockMalformed},
		{"no signatures", `{"format":1,"signatures":[]}`, ErrSigBlockMalformed},
		{"unknown alg", `{"format":1,"signatures":[{"role":"developer","alg":"rsa","key_id":"k","key":"a","sig":"s"}]}`, ErrUnknownSigAlg},
		{"unknown role", `{"format":1,"signatures":[{"role":"wizard","alg":"ed25519","key_id":"k","key":"a","sig":"s"}]}`, ErrUnknownSignerRole},
		{"developer without key", `{"format":1,"signatures":[{"role":"developer","alg":"ed25519","key_id":"k","sig":"s"}]}`, ErrSigBlockMalformed},
		{"empty sig", `{"format":1,"signatures":[{"role":"oem-app","alg":"ed25519","key_id":"k","sig":""}]}`, ErrSigBlockMalformed},
		{"dup key_id", `{"format":1,"signatures":[
			{"role":"developer","alg":"ed25519","key_id":"k","key":"a","sig":"s"},
			{"role":"oem-app","alg":"ed25519","key_id":"k","sig":"s"}]}`, ErrDuplicateKeyID},
	}
	for _, c := range cases {
		if _, err := ParseSignatureBlock([]byte(c.data)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestParseSignatureBlock_Lineage(t *testing.T) {
	valid := `{"format":1,
		"signatures":[{"role":"developer","alg":"ed25519","key_id":"sha256:ccc","key":"a","sig":"s"}],
		"lineage":{"format":1,"nodes":[
			{"key_id":"sha256:aaa","key":"a"},
			{"key_id":"sha256:bbb","key":"b","signed_by_prev":"sig"},
			{"key_id":"sha256:ccc","key":"c","signed_by_prev":"sig"}
		]}}`
	if _, err := ParseSignatureBlock([]byte(valid)); err != nil {
		t.Fatalf("valid lineage rejected: %v", err)
	}

	cases := []struct {
		name string
		data string
	}{
		{"root with signed_by_prev", `{"format":1,
			"signatures":[{"role":"developer","alg":"ed25519","key_id":"k","key":"a","sig":"s"}],
			"lineage":{"format":1,"nodes":[{"key_id":"a","key":"a","signed_by_prev":"x"}]}}`},
		{"non-root without signed_by_prev", `{"format":1,
			"signatures":[{"role":"developer","alg":"ed25519","key_id":"k","key":"a","sig":"s"}],
			"lineage":{"format":1,"nodes":[{"key_id":"a","key":"a"},{"key_id":"b","key":"b"}]}}`},
		{"empty node", `{"format":1,
			"signatures":[{"role":"developer","alg":"ed25519","key_id":"k","key":"a","sig":"s"}],
			"lineage":{"format":1,"nodes":[{"key_id":"","key":""}]}}`},
	}
	for _, c := range cases {
		if _, err := ParseSignatureBlock([]byte(c.data)); !errors.Is(err, ErrLineageMalformed) {
			t.Errorf("%s: err = %v, want ErrLineageMalformed", c.name, err)
		}
	}
}
