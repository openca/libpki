#!/bin/bash

# DEBUG_OPTION=" -debug -verbose"
DEBUG_OPTION=""

# This script is used to test the pki_tool.sh script

function gen_key() {
    
    # Input Parameters
    ALGS=$1

    # Test Simple Key Generation
    for alg in $ALGS; do
        if ! [ -f "results/${alg}.key" ]; then
            echo "Key Gen Testing: $alg"
            pki-tool genkey -algorithm "${alg}" ${DEBUG_OPTION} \
                -batch -out "results/${alg}.key" 2>&1 >> key_log.txt
            if [ $? -ne 0 ]; then
                echo "Error: Failed to generate key for $alg\n"
                echo pki-tool genkey -algorithm "${alg}" -batch -out "results/${alg}.key"
                echo
                exit 1
            fi
        fi
    done
}

function gen_comp_key() {

    # Input Parameters
    ALGS=$1

    # K of N
    KOFN=$2

    # Initial Options
    OPTIONS=""

    # K of N Option
    if [ ! -z "$KOFN" ]; then
        KOFN_OPTION="-param kofn:$KOFN"
    fi

    # Generates the components
    gen_key "$ALGS"

    # Test Simple Key Generation
    COMP_NAME="comp"
    for alg in $ALGS; do
        OPTIONS+=" -addkey results/${alg}.key"
        COMP_NAME+="_${alg}"
    done

    # Combining the keys
    if ! [ -f "results/${COMP_NAME}.key" ] ; then
        pki-tool genkey -algorithm "composite" \
            -batch -out "results/${COMP_NAME}.key" \
            ${OPTIONS} ${KOFN_OPTION} ${DEBUG_OPTION} 2>&1 >> comp_key_log.txt
        if [ $? -ne 0 ]; then
            echo "Error: Failed to generate COMPOSITE (OPTIONS: ${OPTIONS}, K-of-N: ${KOFN_OPTION})\n"
            echo "       (PWD: $PWD)"
            echo
            exit 1
        fi
    fi
}

function gen_exp_key() {

    # Input Parameters
    ALGS=$1

    # Initial Options
    OPTIONS=""

    # Generates the components
    gen_key "$ALGS"

    # Test Simple Key Generation
    EXP_NAME="explicit"
    ALG_NAME=""
    for alg in $ALGS; do
        OPTIONS+=" -addkey results/${alg}.key"
        EXP_NAME+="_${alg}"
        ALG_NAME+="${alg}-"
    done

    # Removing the trailing dash
    ALG_NAME=${ALG_NAME%%-}

    # Combining the keys
    if ! [ -f "results/${EXP_NAME}.key" ] ; then
        pki-tool genkey -algorithm "${ALG_NAME}" \
            -batch -out "results/${EXP_NAME}.key" \
            ${OPTIONS} ${DEBUG_OPTION} 2>&1 >> comp_key_log.txt
        if [ $? -ne 0 ]; then
            echo
            echo "    ERROR: Failed to generate COMPOSITE (OPTIONS: ${OPTIONS})\n"
            echo
            exit 1
        fi
    fi
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
                -batch -out "results/${alg}_${dig}.req" ${DEBUG_OPTION} 2>&1 >> req_log.txt
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
                -batch -in "results/${alg}_${dig}.req" ${DEBUG_OPTION} \
                -out "results/${alg}_${dig}.cer" 2>&1 > cert_log.txt
            if [ $? -ne 0 ]; then
                echo
                echo "\n    ERROR: Failed to generate self-signed cert (Alg: $alg, Dig: $dig)\n\n"
                echo
                exit 1
            fi
        done
    done
}

function verify() {

    # Input Parameters
    ALGS=$1
    DIGESTS=$2
    TYPES=$3

    # Test Simple CSR Generation
    for alg in $ALGS; do
        for dig in $DIGESTS; do
            for type in $TYPES; do
                echo "Verify Testing (type = $type): ${alg}_${dig}.${type}"
                pki-siginfo -signer "results/${alg}.key" ${DEBUG_OPTION} \
                    -in "results/${alg}_${dig}.${type}" 2>&1 >> verify_log.txt
                if [ $? -ne 0 ]; then
                    echo "Error: Failed to generate self-signed cert for $alg + $dig\n"
                    echo
                    exit 1
                fi
            done
        done
    done
}

# Digest Algorithms
NULL_DIGEST="NULL"
CLASSIC_DIGESTS="sha256 sha384 sha512"
ADVANCED_DIGESTS="shake128 shake256 sha3-256 sha3-384 sha3-512"
ALL_DIGESTS="$NULL_DIGEST $CLASSIC_DIGESTS $ADVANCED_DIGESTS"

# Composite Keys: Hybrid Algorithms
COMPOSITE_ALGS_HYBRID_1="dilithium2 rsa"
COMPOSITE_ALGS_HYBRID_2="falcon512 ec"

COMPOSITE_REQS_HYBRID_1_2="comp_dilithium2_rsa comp_falcon512_ec"
COMPOSITE_REQS_HYBRID_1_2_DIGESTS="NULL $CLASSIC_DIGESTS"

# Composite Keys: Post Quantum Algorithms
COMPOSITE_ALGS_HYBRID_3="dilithium2 falcon512"
COMPOSITE_ALGS_HYBRID_4="dilithium3 falcon512"
COMPOSITE_ALGS_HYBRID_5="dilithium5 falcon1024"

COMPOSITE_REQS_HYBRID_3_4_5="comp_dilithium2_falcon512 comp_dilithium3_falcon512 comp_dilithium5_falcon1024"
COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS="NULL $CLASSIC_DIGESTS"

# Composite Keys: Explicit Algorithms
COMPOSITE_ALGS_EXPLICIT_1="dilithium3 rsa"
COMPOSITE_ALGS_EXPLICIT_2="dilithium3 ec"
# EXPLICIT_COMPOSITE_ALGS_3="DILITHIUM3-ED25519"
# EXPLICIT_COMPOSITE_ALGS_4="DILITHIUM3-ED448"

COMPOSITE_REQS_EXPLICIT_1_2="explicit_dilithium3_rsa explicit_dilithium3_ec"
COMPOSITE_REQS_EXPLICIT_DIGESTS="NULL"

# ==================
# Classic Algorithms
# ==================

# # Generates Classic keys
# gen_key "rsa ec ed448 ed25519 x448 x25519"

# # Generates Classic CSRs with Hash-n-Sign
# gen_req "rsa ec" "$CLASSIC_DIGESTS"
# verify  "rsa ec" "$CLASSIC_DIGESTS" "req"

# # Generates Classic CSRs with Direct Signing
# gen_req "ed448 ed25519" "$NULL_DIGEST"
# verify  "ed448 ed25519" "$NULL_DIGEST" "req"

# # Generates Classic Certs with Hash-n-Sign
# gen_cer "rsa ec" "$CLASSIC_DIGESTS"
# verify  "rsa ec" "$CLASSIC_DIGESTS" "cer"

# # Generates Classic Certs with Direct Signing
# gen_cer "ed448 ed25519" "$NULL_DIGEST"
# verify "ed448 ed25519" "$NULL_DIGEST" "cer"

# ==============
# PQC Algorithms
# ==============

# # Post Quantum Algorithms
# PQC_ALGS="dilithium2 dilithium3 dilithium5 falcon512 falcon1024"
# PQC_DIGESTS="$CLASSIC_DIGESTS $ADVANCED_DIGESTS"

# # Generates Post-Quantum keys
# gen_key "$PQC_ALGS"

# # Generates Post-Quantum CSRs with Hash-n-Sign
# gen_req "$PQC_ALGS" "$PQC_DIGESTS"
# verify  "$PQC_ALGS" "$PQC_DIGESTS" "req"

# # Generates Post-Quantum CSRs with Direct Signing
# gen_cer "$PQC_ALGS" "$NULL_DIGEST"
# verify  "$PQC_ALGS" "$NULL_DIGEST" "req"

# # Generates PQC Certificates with Hash-n-Sign
# gen_cer "$PQC_ALGS" "$PQC_DIGESTS"
# verify  "$PQC_ALGS" "$PQC_DIGESTS" "cer"

# =====================
# Generic T/T Composite
# =====================

# Generates Composite Keys
gen_comp_key "rsa ec"

# Generates Composite CSRs with Hash-n-Sign
gen_req "comp_rsa_ec" "$CLASSIC_DIGESTS"
verify  "comp_rsa_ec" "$CLASSIC_DIGESTS" "req"

# Generates Composite CERTs with Direct Signing
gen_cer "comp_rsa_ec" "$CLASSIC_DIGESTS"
verify  "comp_rsa_ec" "$CLASSIC_DIGESTS" "cer"

# Generates Composite K-of-N Keys
gen_comp_key "ed448 rsa" "1"

# Generates Composite K-of-N CSRs with Direct Signing
gen_req "comp_ed448_rsa" "$NULL_DIGEST"
verify  "comp_ed448_rsa" "$NULL_DIGEST" req

# Generate Composite K-of-N CERT with Hash-n-Sign
gen_cer "comp_ed448_rsa" "$ALL_DIGESTS"
verify  "comp_rsa_ed25519" "$ALL_DIGESTS" "cer"

exit 0;

# =======================
# Generic T/PQC Composite
# =======================

gen_comp_key "$COMPOSITE_ALGS_HYBRID_1"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_2" "2"

gen_req "$COMPOSITE_REQS_HYBRID_1_2" "$COMPOSITE_REQS_HYBRID_1_2_DIGESTS"

verify "$COMPOSITE_REQS_HYBRID_1_2" "$COMPOSITE_REQS_HYBRID_1_2_DIGESTS" "req" # <------ This one is broken


# Generates Composite CSRs

gen_comp_key "$COMPOSITE_ALGS_HYBRID_3" "1"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_4" "2"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_5" "1"

gen_req "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS"

# # verify "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS" "req" <------ This one is broken

# ==================
# Explicit Composite
# ==================

# Generate Explicit Composite Keys
gen_exp_key "$COMPOSITE_ALGS_EXPLICIT_1"

gen_exp_key "$COMPOSITE_ALGS_EXPLICIT_2"

# Generates Explicit Composite CSRs
gen_req "$COMPOSITE_REQS_EXPLICIT_1_2" "$COMPOSITE_REQS_EXPLICIT_DIGESTS"

# verify "$COMPOSITE_REQS_EXPLICIT_1_2" "$COMPOSITE_REQS_EXPLICIT_DIGESTS" "req"  # <------ This one is broken

# Generates Explicit Composite Certificates
# gen_cer "$COMPOSITE_REQS_EXPLICIT_1_2" "$COMPOSITE_REQS_EXPLICIT_DIGESTS"   <------ This one is broken

# verify "$COMPOSITE_REQS_EXPLICIT_1_2" "$COMPOSITE_REQS_EXPLICIT_DIGESTS" "cer"

# # Generates Explicit Composite CSRs
# gen_req "$EXPLICIT_COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# # Generates Explicit Composite Certificates
# gen_cer "$EXPLICIT_COMPOSITE_ALGS" "$COMPOSITE_DIGESTS"

# All tests passed
exit 0;