// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"
)

// deviceOrg marks a caravel device leaf's Organization.
const deviceOrg = "PharosVPN Device"

// DeviceCert is a caravel device identity coxswain issued from the Device CA: the
// leaf plus the generated private key. Unlike node/relay certs (CSR-signed, the
// key kept by the holder), the manual-bundle flow generates the key here so the
// whole identity travels in one file the operator copies to the device. (The
// enrollment-token flow will instead sign a device-supplied CSR — same leaf
// shape, key never leaves the device.)
type DeviceCert struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// IssueDeviceCert issues a one-year caravel device leaf off the Device CA, with
// the ClientAuth EKU it presents in mTLS to the relay. label is recorded as the
// CN for auditing (e.g. the user's email or a device name); it carries no
// authority — AccountSync authorizes on the session token from Authenticate, not
// the certificate subject.
func IssueDeviceCert(deviceCA Authority, label string) (DeviceCert, error) {
	if deviceCA.Role != RoleDevice {
		return DeviceCert{}, fmt.Errorf("IssueDeviceCert: expected device CA, got %q", deviceCA.Role)
	}
	if label == "" {
		label = "caravel-device"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return DeviceCert{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return DeviceCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: label, Organization: []string{deviceOrg}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, deviceCA.Cert, &key.PublicKey, deviceCA.Key)
	if err != nil {
		return DeviceCert{}, fmt.Errorf("IssueDeviceCert: sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return DeviceCert{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return DeviceCert{}, err
	}
	return DeviceCert{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
