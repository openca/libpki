#!/bin/bash

# This script is used to test the pki_tool.sh script

ADVANCED_DIGESTS="shake128 shake256 sha3-256 sha3-384 sha3-512"

# CLASSIC_ALGS="rsa ec ed25519 ed448"
CLASSIC_ALGS="rsa ec"
CLASSIC_DIGESTS="sha256 sha384 sha512"

PQC_ALGS="dilithium2 dilithium3 dilithium5 falcon512 falcon1024"
PQC_DIGESTS="NULL $CLASSIC_DIGESTS"

COMPOSITE_ALGS="COMPOSITE"
COMPOSITE_DIGESTS="NULL $CLASSIC_DIGESTS $ADVANCED_DIGESTS"

EXPLICIT_COMPOSITE_ALGS="DILITHIUM3-RSA DILITHIUM3-EC DILITHIUM3-ED25519 DILITHIUM3-ED448"
EXPLICIT_COMPOSITE_DIGESTS="NULL"

function gen_key() {
    
    # Input Parameters
    ALGS=$1

    # Test Simple Key Generation
    for alg in $ALGS; do
        echo "Key Gen Testing: $alg"
        pki-tool genkey -algorithm "${alg}" \
            -batch -out "results/${alg}.key" 2>&1 > log.txt
        if [ $? -ne 0 ]; then
            echo "Error: Failed to generate key for $alg\n"
            echo pki-tool genkey -algorithm "${alg}" -batch -out "results/${alg}.key"
            echo
            exit 1
        fi
    done
}

function gen_req() {

    # Input Parameters
    ALGS=$1
    DIGESTS=$2

    # Test Simple CSR Generation
    for alg in $ALGS; do
        for dig in $DIGESTS; do
            echo "Req Gen Testing: $alg + $dig"
            pki-tool genreq -digest "${dig}" -signkey "results/${alg}.key" \
                -batch -out "results/${alg}_${dig}.req" 2>&1 > log.txt
            if [ $? -ne 0 ]; then
                echo "Error: Failed to generate key for $alg + $dig\n"
                echo pki-tool genreq -batch -digest "${dig}" -signkey "results/${alg}.key"
                echo
                exit 1
            fi
        done
    done

}

function gen_cer() {

    # Input Parameters
    ALGS=$1
    DIGESTS=$2

    # Test Simple CSR Generation
    for alg in $ALGS; do
        for dig in $DIGESTS; do
            echo "Cer Gen Testing: $alg + $dig"
            pki-tool gencert -selfsign -digest "${dig}" -signkey "results/${alg}.key" \
                -batch -in "results/${alg}_${dig}.req" \
                -out "results/${alg}_${dig}.cer" 2>&1 > log.txt
            if [ $? -ne 0 ]; then
                echo "Error: Failed to generate self-signed cert for $alg + $dig\n"
                echo
                exit 1
            fi
        done
    done

}

# ==================
# Classic Algorithms
# ==================

# Generates Classic keys
gen_key "$CLASSIC_ALGS"

# Generates Classic CSRs
gen_req "$CLASSIC_ALGS" "$CLASSIC_DIGESTS"

# Generates Classic CSRs
gen_cer "$CLASSIC_ALGS" "$CLASSIC_DIGESTS"

# ==============
# PQC Algorithms
# ==============

# Generates Post-Quantum keys
gen_key "$PQC_ALGS"

# Generates PQC CSRs
gen_req "$PQC_ALGS" "$PQC_DIGESTS"

# Generates PQC Certificates
gen_cer "$PQC_ALGS" "$PQC_DIGESTS"

# # =================
# # Generic Composite
# # =================

# # Generates Composite Keys
# gen_comp_key "$COMPOSITE_ALGS"

# # Generates Composite CSRs
# gen_req "$COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# # Generates Composite Certificates
# gen_cer "$COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# # ==================
# # Explicit Composite
# # ==================

# # Generate Explicit Composite Keys
# gen_comp_key "$EXPLICIT_COMPOSITE_ALGS"

# # Generates Explicit Composite CSRs
# gen_req "$EXPLICIT_COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# # Generates Explicit Composite Certificates
# gen_cer "$EXPLICIT_COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# All tests passed
exit 0;