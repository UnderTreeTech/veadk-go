package veauth

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempCredential(t *testing.T, dir string, ak, sk, st string) string {
	t.Helper()
	p := filepath.Join(dir, "cred.json")
	data := []byte("{\"access_key_id\":\"" + ak + "\",\"secret_access_key\":\"" + sk + "\",\"session_token\":\"" + st + "\"}")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}

func TestGetCredentialFromVeFaaSIAM_OK(t *testing.T) {
	dir := t.TempDir()
	p := writeTempCredential(t, dir, "ak", "sk", "st")
	cred, err := GetCredentialFromVeFaaSIAM(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.AccessKeyID != "ak" || cred.SecretAccessKey != "sk" || cred.SessionToken != "st" {
		t.Fatalf("unexpected credential values")
	}
}

func TestGetCredentialFromVeFaaSIAM_FileNotFound(t *testing.T) {
	_, err := GetCredentialFromVeFaaSIAM(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestGetCredentialFromVeFaaSIAM_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := GetCredentialFromVeFaaSIAM(p)
	if err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestRefreshAKSK_WithKeys(t *testing.T) {
	cred, err := RefreshAKSK("ak", "sk")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.AccessKeyID != "ak" || cred.SecretAccessKey != "sk" || cred.SessionToken != "" {
		t.Fatalf("unexpected credential values")
	}
}
