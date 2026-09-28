package main

// Windows keeps the private key in the machine-scoped software CNG provider.
// Only its public certificate is a PEM file. No TPM, AD, user impersonation,
// or exportable device-key.pem is required.
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ncrypt = windows.NewLazySystemDLL("ncrypt.dll")
var ncOpenProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
var ncOpenKey = ncrypt.NewProc("NCryptOpenKey")
var ncCreateKey = ncrypt.NewProc("NCryptCreatePersistedKey")
var ncGetProperty = ncrypt.NewProc("NCryptGetProperty")
var ncSetProperty = ncrypt.NewProc("NCryptSetProperty")
var ncFinalize = ncrypt.NewProc("NCryptFinalizeKey")
var ncExport = ncrypt.NewProc("NCryptExportKey")
var ncSign = ncrypt.NewProc("NCryptSignHash")
var ncFree = ncrypt.NewProc("NCryptFreeObject")
var ncDelete = ncrypt.NewProc("NCryptDeleteKey")

const ncMachine = 0x20
const ncSilent = 0x40

func utf16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }
func ncError(op string, status uintptr) error {
	return fmt.Errorf("CNG %s failed: 0x%08x", op, uint32(status))
}
func cngKeyName(etc string) (string, error) {
	path, err := filepath.Abs(etc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return fmt.Sprintf("Pow3rTool-RCON-%x", sum[:16]), nil
}
func cngProvider() (uintptr, error) {
	var p uintptr
	s, _, _ := ncOpenProvider.Call(uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(utf16("Microsoft Software Key Storage Provider"))), 0)
	if s != 0 {
		return 0, ncError("open provider", s)
	}
	return p, nil
}
func cngOpen(name string, create bool) (uintptr, error) {
	p, err := cngProvider()
	if err != nil {
		return 0, err
	}
	defer ncFree.Call(p)
	var key uintptr
	s, _, _ := ncOpenKey.Call(p, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16(name))), 0, ncMachine|ncSilent)
	if s == 0 {
		if err := validateCNGKey(key); err != nil {
			ncFree.Call(key)
			return 0, err
		}
		return key, nil
	}
	if !create || (uint32(s) != 0x80090016 && uint32(s) != 0x80090011) {
		return 0, ncError("open key", s)
	}
	s, _, _ = ncCreateKey.Call(p, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(utf16("ECDSA_P256"))), uintptr(unsafe.Pointer(utf16(name))), 0, ncMachine)
	if s != 0 {
		return 0, ncError("create key", s)
	}
	ok := false
	defer func() {
		if !ok {
			// DeleteKey frees the handle on success.
			if code, _, _ := ncDelete.Call(key, ncSilent); code != 0 {
				ncFree.Call(key)
			}
		}
	}()
	var exportPolicy uint32 // zero means no private-key export
	s, _, _ = ncSetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Export Policy"))),
		uintptr(unsafe.Pointer(&exportPolicy)), 4, 0)
	if s != 0 {
		return 0, ncError("set export policy", s)
	}
	s, _, _ = ncFinalize.Call(key, ncSilent)
	if s != 0 {
		return 0, ncError("finalize key", s)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return 0, err
	}
	s, _, _ = ncSetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Security Descr"))),
		uintptr(unsafe.Pointer(sd)), uintptr(sd.Length()), uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)|0x80000000)
	if s != 0 {
		return 0, ncError("set key ACL", s)
	}
	if err := validateCNGKey(key); err != nil {
		return 0, err
	}
	ok = true
	return key, nil
}

// Reusing a persisted name is safe only if its owner, ACL and export policy
// still match the machine-identity boundary. Do not silently adopt or repair a
// pre-created/exportable key: it might already have been copied.
func cngProperty(key uintptr, name string, flags uintptr) ([]byte, error) {
	var n uint32
	code, _, _ := ncGetProperty.Call(key, uintptr(unsafe.Pointer(utf16(name))), 0, 0, uintptr(unsafe.Pointer(&n)), flags)
	if code != 0 {
		return nil, ncError("get "+name+" size", code)
	}
	if n == 0 || n > 65536 {
		return nil, fmt.Errorf("invalid CNG property length")
	}
	raw := make([]byte, n)
	code, _, _ = ncGetProperty.Call(key, uintptr(unsafe.Pointer(utf16(name))), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)), flags)
	if code != 0 {
		return nil, ncError("get "+name, code)
	}
	if n > uint32(len(raw)) {
		return nil, fmt.Errorf("CNG property length changed")
	}
	return raw[:n], nil
}
func validateCNGKey(key uintptr) error {
	policy, err := cngProperty(key, "Export Policy", ncSilent)
	if err != nil {
		return err
	}
	if len(policy) != 4 || binary.LittleEndian.Uint32(policy) != 0 {
		return fmt.Errorf("refusing exportable CNG identity key")
	}
	raw, err := cngProperty(key, "Security Descr", uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION))
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(raw)
	if len(raw) < 20 {
		return fmt.Errorf("invalid CNG security descriptor")
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&raw[0]))
	if !sd.IsValid() {
		return fmt.Errorf("invalid CNG security descriptor")
	}
	return validateWindowsSecurity(sd, true)
}

type cngSigner struct {
	name string
	pub  *ecdsa.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.pub }
func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != 32 || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("CNG P-256 signer requires SHA-256")
	}
	key, err := cngOpen(s.name, false)
	if err != nil {
		return nil, err
	}
	defer ncFree.Call(key)
	raw := make([]byte, 64)
	var n uint32
	code, _, _ := ncSign.Call(key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)), ncSilent)
	if code != 0 {
		return nil, ncError("sign", code)
	}
	if n != 64 {
		return nil, fmt.Errorf("unexpected CNG signature length %d", n)
	}
	// CNG returns fixed-width r||s; Go TLS and CSRs need ASN.1 DER.
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
}
func openDeviceSigner(etc string, create bool) (crypto.Signer, error) {
	name, err := cngKeyName(etc)
	if err != nil {
		return nil, err
	}
	key, err := cngOpen(name, create)
	if err != nil {
		return nil, err
	}
	defer ncFree.Call(key)
	raw := make([]byte, 72)
	var n uint32
	code, _, _ := ncExport.Call(key, 0, uintptr(unsafe.Pointer(utf16("ECCPUBLICBLOB"))), 0,
		uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)), 0)
	if code != 0 {
		return nil, ncError("export public key", code)
	}
	if n != 72 || binary.LittleEndian.Uint32(raw[:4]) != 0x31534345 || binary.LittleEndian.Uint32(raw[4:8]) != 32 {
		return nil, fmt.Errorf("unexpected CNG P-256 public key format")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[8:40]), Y: new(big.Int).SetBytes(raw[40:72])}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("CNG public key is not on P-256")
	}
	return &cngSigner{name: name, pub: pub}, nil
}
func loadDeviceKey(etc string) (crypto.Signer, error)   { return openDeviceSigner(etc, false) }
func createDeviceKey(etc string) (crypto.Signer, error) { return openDeviceSigner(etc, true) }
