# Go Certificate Generator

This Go program generates a self-signed ECDSA certificate and private key. It uses the `ecdsa` package and `elliptic.P384()` curve to create the key pair and outputs the certificate in PEM format. The certificate can be used for SSL/TLS purposes, or any other use case where an X.509 certificate is needed.

## Features
- Generates an ECDSA private key using the `elliptic.P384()` curve.
- Creates a self-signed X.509 certificate with basic fields (Organization, Subject, Validity).
- Outputs the certificate and private key in PEM format.
- The certificate is valid for 1 year.

## Requirements

- Go 1.16 or higher.
- A working Go environment. (If Go is not installed, follow the installation instructions from [Go's official website](https://golang.org/doc/install)).

## Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/certificate-generator.git
cd certificate-generator
