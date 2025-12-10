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

func TestGetCredentialFromVeFaaSIAM_Local(t *testing.T) {
	cred, err := GetCredentialFromVeFaaSIAM("../../.credential")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.AccessKeyID != "AKTP0CO9liXQtdQVCkIxAADJh6bX6HqQ7S" || cred.SecretAccessKey != "HGsJNx8GiQ" || cred.SessionToken != "nChBqZkpORjIxOG1LVVBrdGYOUvjsyfxVdDafKYQ2e_fyQYYmcHiyQYgn9LF6QcoBDCxmrghOjpGb3JjZUFnZW50Um9sZS92ZWZhYXMtYWYzMzZmODktMWIyYi00ZDFhLWEyZTQtMjg1N2E3ZWEwY2EyQgZ2ZWZhYXNKQnsiU3RhdGVtZW50IjpbeyJFZmZlY3QiOiJBbGxvdyIsIkFjdGlvbiI6WyIqIl0sIlJlc2IjpbIioiXX1dfVIrdmVmYWFzLWFmMzM2Zjg5LTFiMmItNGQxYS1hMmU0LTI4NTdhN2VhMGNhMlgDegZ2ZWZhYXM.BLnIhN6Emd_3EMAIL48s6tgea8Z-C3M3zeXlL4FPFHQGYVBbzlD3z0wH4cL9eJB5np83K3PdU3O7f6mwI7cSQg" {
		t.Fatalf("unexpected credential values")
	}
}
