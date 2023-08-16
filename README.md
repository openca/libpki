# The LibPKI Project

## Introduction

The LibPKI Project is aimed to provide an easy-to-use PKI library for PKI
enabled application development. The library provides the developer with all
the needed functionalities to manage all major cryptographic data structures
and associated prcedures, from generation to validation.

Ultimately, the LibPKI Project enables developers with the possibility to implement complex
cryptographic operations with a few simple function calls by implementing an
high-level cryptographic API.

You can find more inforamtion about this project and many more at our website: [The OpenCA Labs and Projects](https://www.openca.org/).

## Building the library and tools

LibPKI uses standard autoconf & automake tools for the configuration, compiling, and
installation of the library and the associated SDK. To see all the different options
available for compilation, you can use the following command:

```bash
$ ./configure --help
```

A typical set of options is as follows:

```bash
$ ./configure --prefix=/opt/crypto --with-openssl-prefix=/opt/crypto \
      --enable-extra-checks --enable-composite --disable-ldap
```

Although we try to support as many platforms as we can, there might be some options
that are specific for your system that we might not be aware of. Please report the
possible compilation issues through the GitHub interface or by sending an e-mail
at madwolf -at- openca -dot- org.

## Adding support for Quantum-Safe algorithms

LibPKI supports the use of the OQS library through the OpenSSL-OQS wrapper from
the Open Quantum Safe project: [The Open Quantum Safe project (OQS)](https://openquantumsafe.org/). Specifically, LibPKI currently supports the OpenSSL-OQS 1.1.1x branch with the appropriate patches to provide hash-n-sign functionality (not
provided via the vanilla OQS project).

To ease the compilation of the LibPKI library and the
dependencies for Quantum-Safe algorithms, you can download the repository:

- [The LibPKI-PQC repo](https://github.com/opencrypto/libpki-pqc)

Once downloaded, go in the `libpki-pqc` project's directory and use the `build.sh`
script (or the `build-debug.sh``) to build and install all dependencies (but
the development tools themselves).

Here's an example usage for building a debug version of the libraries:

```bash
  $ ./build.sh /opt/libpki-pqc
```

The script provides some help in building, patching, and installing all the needed
libraries and dependencies. Specifically, it completes the following actions:

- Download, Compile, and Install the [OQS library](https://github.com/open-quantum-safe/liboqs)
- Download, Compile, PATCH, and Install the [OQS OpenSSL Wrapper](https://github.com/open-quantum-safe/openssl)
- Download, Compile, and Install the [LibPKI library](https://github.com/openca/libpki)

The specific patching that we do for the OpenSSL wrapper enables:

- The use of `hash-n-sign` paradigm with all PQC algorithms
- Allows the generation/use of RSA keys smaller than 512 bits

You can review the patched code in the `config-n-patch/ossl-replace/20230525/` 
directory of the repository and [in the GitHub repository](https://github.com/opencrypto/libpki-pqc/tree/main/config-n-patch/ossl-replace/20230525).


### Hybrid Keys and Certificates (Composite Crypto)

LibPKI supports the use of [Composite Cryptography](https://datatracker.ietf.org/doc/draft-ounsworth-pq-composite-sigs/) to enable hybrid signature schemes. Specifically, LibPKI supports both the generic version of Composite Crypto that allows to combine any number of algorithms and the explicit version of Composite Crypto that identifies
well-known combinations with specific OIDs used in both public keys' and signatures'
identifiers.

For example, to compose an RSA key and a Falcon key, you can use the following commands and the generic version of Composite Crypto:

```bash
  $ pki-tool genkey -algor RSA -sec_bits 112 -out rsa.key
  $ pki-tool genkey -algor Falcon -sec_bits 128 -out falcon512.key
  $ pki-tool genkey -algor Composite -addkey rsa.key -addkey falcon512.key \
      -out composite_rsa_falcon.key
```
The generated key is saved in `composite_rsa_falcon.key` file and stores
both the RSA and Falcon512 keys (public and private).

To generate an explicit combination, instead, you first generate the individual keys
and then put them together in a single explicit Composite Key:

```bash
  $ pki-tool genkey -algor ED25519 -out ed25519.key
  $ pki-tool genkey -algor Falcon -sec_bits 128 -out falcon512.key
  $ pki-tool genkey -algor FALCON-ED25519 -addkey falcon512.key \
      -addkey falcon512.key -out composite_rsa_falcon.key
```

In this case, the generated key is saved in the `explicit_falcon_ed25519.key` file
that stores both the Falcon and Ed25519 keys (both private and public).

# Acknowledgments:

The this project has been supported by the following entities:

- **OpenCA Laboratories ( Jan 2007 - Now ).**
This software has been released and supported by the OpenCA Labs and its
projects related to PKIs. The software will continuosly be updated and
used for several other projects including, but not limited to, OpenCA
OCSP responder, OpenCA PKI Next Generation, and OpenCA PRQP Server.

- **CableLabs Television Laboratories (Jan 2019 - Now).** 
The CableLabs organization has been supporting the LibPKI project and its
evolution (especially the integration of innovative features such as the
support for Composite Cryptography and Quantum-Safe algorithms).

- **U.S. Department of Homeland Security (Jan 2007 - Mar 2009).**
This software results from a research program in the Institute for Security
Technology Studies at Dartmouth College, supported by the U.S. Department of
Homeland Security under Grant Award Number 2006-CS-001-000001. The views and
conclusions contained in this document are those of the authors and should
not be interpreted as necessarily representing the official policies, either
expressed or implied, of the U.S. Department of Homeland Security.

We also want to thank all the contributors that have been submitting issues,
pull requests, and patches for the library - thank you!
