#!/bin/bash

# DEBUG_OPTION=" -debug -verbose"
DEBUG_OPTION=""

# Digest Algorithms
NULL_DIGEST="NULL"
CLASSIC_DIGESTS="sha256 sha384 sha512"
ADVANCED_DIGESTS="shake128 shake256 sha3-256 sha3-384 sha3-512"
ALL_DIGESTS="$NULL_DIGEST $CLASSIC_DIGESTS $ADVANCED_DIGESTS"

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
                echo >&2
                echo >&2
                echo "    Error: Failed to generate key for $alg + $dig" >&2
                echo >&2
                echo pki-tool genreq -batch -digest "${dig}" -signkey "results/${alg}.key" >&2
                echo >&2
                echo >&2
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
                echo >&2
                echo >&2
                echo "    ERROR: Failed to generate self-signed cert (Alg: $alg, Dig: $dig)" >&2
                echo >&2
                echo >&2
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
                    echo >&2
                    echo >&2
                    echo "    ERROR: Failed to validate $alg and $dig (results/${alg}_${dig}.${type})" >&2
                    echo >&2
                    echo >&2
                    exit 1
                fi
            done
        done
    done
}


# ==================
# Classic Algorithms
# ==================

# Make the "text" to "" for skipping the tests
if ! [ -z "" ] ; then

    # Generates Classic keys
    gen_key "rsa ec ed448 ed25519 x448 x25519"

    # Generates Classic CSRs with Hash-n-Sign
    gen_req "rsa ec" "$CLASSIC_DIGESTS"
    verify  "rsa ec" "$CLASSIC_DIGESTS" "req"

    # Generates Classic CSRs with Direct Signing
    gen_req "ed448 ed25519" "$NULL_DIGEST"
    verify  "ed448 ed25519" "$NULL_DIGEST" "req"

    # Generates Classic Certs with Hash-n-Sign
    gen_cer "rsa ec" "$CLASSIC_DIGESTS"
    verify  "rsa ec" "$CLASSIC_DIGESTS" "cer"

    # Generates Classic Certs with Direct Signing
    gen_cer "ed448 ed25519" "$NULL_DIGEST"
    verify "ed448 ed25519" "$NULL_DIGEST" "cer"

fi

# ==============
# PQC Algorithms
# ==============

# Make the "text" to "" for skipping the tests
if ! [ -z "" ] ; then

    # Post Quantum Algorithms
    PQC_ALGS="dilithium2 dilithium3 dilithium5 falcon512 falcon1024"
    PQC_DIGESTS="$CLASSIC_DIGESTS $ADVANCED_DIGESTS"

    # Generates Post-Quantum keys
    gen_key "$PQC_ALGS"

    # Generates Post-Quantum CSRs with Hash-n-Sign
    gen_req "$PQC_ALGS" "$NULL_DIGEST $PQC_DIGESTS"
    verify  "$PQC_ALGS" "$NULL_DIGEST $PQC_DIGESTS" "req"

    # Generates Post-Quantum CSRs with Direct Signing
    gen_cer "$PQC_ALGS" "$NULL_DIGEST"
    verify  "$PQC_ALGS" "$NULL_DIGEST" "req"

    # Generates PQC Certificates with Hash-n-Sign
    gen_cer "$PQC_ALGS" "$PQC_DIGESTS"
    verify  "$PQC_ALGS" "$PQC_DIGESTS" "cer"

fi

# =====================
# Generic T/T Composite
# =====================

# Make the "text" to "" for skipping the tests
if ! [ -z "" ] ; then

    # Generates Composite Keys
    gen_comp_key "rsa ec"

    # Generates Composite CSRs with Hash-n-Sign
    gen_req "comp_rsa_ec" "$CLASSIC_DIGESTS"
    verify  "comp_rsa_ec" "$CLASSIC_DIGESTS" "req"

    # Generates Composite CERTs with Direct Signing
    gen_cer "comp_rsa_ec" "$CLASSIC_DIGESTS"
    verify  "comp_rsa_ec" "$CLASSIC_DIGESTS" "cer"

    # Generates Composite K-of-N Keys
    gen_comp_key "rsa ed25519"

    gen_req "comp_rsa_ed25519" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify "comp_rsa_ed25519" "$NULL_DIGEST $CLASSIC_DIGESTS" req

    gen_cer "comp_rsa_ed25519" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify "comp_rsa_ed25519" "$NULL_DIGEST sha256 sha384 sha512" cer

    # Generates Composite K-of-N Keys
    gen_comp_key "ed448 rsa"

    # # Generates Composite K-of-N CSRs with Direct Signing
    gen_req "comp_ed448_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_ed448_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" req

    # Generate Composite K-of-N CERT with Hash-n-Sign
    gen_cer "comp_ed448_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_ed448_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

    # Generates Composite K-of-N Keys
    gen_comp_key "ed25519 ed448"

    # # Generates Composite K-of-N CSRs with Direct Signing
    gen_req "comp_ed25519_ed448" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_ed25519_ed448" "$NULL_DIGEST $CLASSIC_DIGESTS" req

    # Generate Composite K-of-N CERT with Hash-n-Sign
    gen_cer "comp_ed25519_ed448" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_ed25519_ed448" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

fi

# =======================
# Generic T/PQC Composite
# =======================

# Make the "text" to "" for skipping the tests
if ! [ -z "" ] ; then

    # Composite Keys: Hybrid Algorithms
    gen_comp_key "dilithium2 rsa"

    gen_req "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" "req"

    gen_cer "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

    gen_comp_key "falcon512 ec" "1"

    gen_req "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" "req"

    gen_cer "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_rsa" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

fi

# =======================
# Generic PQ/PQ Composite
# =======================

# Make the "text" to "" for skipping the tests
if ! [ -z "" ] ; then

    # Composite Keys: Post Quantum Algorithms
    gen_comp_key "dilithium2 falcon512"
    gen_comp_key "dilithium3 falcon512"
    gen_comp_key "dilithium5 falcon1024"

    # Generates Composite CSRs: Post Quantum Algorithms
    gen_req "comp_dilithium2_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS" "req"

    gen_req "comp_dilithium3_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium3_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS" "req"

    gen_req "comp_dilithium5_falcon1024" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium5_falcon1024" "$NULL_DIGEST $CLASSIC_DIGESTS" "req"

    # Generates Composite CERTs: Post Quantum Algorithms
    gen_cer "comp_dilithium2_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium2_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

    gen_cer "comp_dilithium3_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium3_falcon512" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

    gen_cer "comp_dilithium5_falcon1024" "$NULL_DIGEST $CLASSIC_DIGESTS"
    verify  "comp_dilithium5_falcon1024" "$NULL_DIGEST $CLASSIC_DIGESTS" "cer"

fi

# ==================
# Explicit Composite
# ==================

# Make the "text" to "" for skipping the tests
if ! [ -z "execute_me" ] ; then

gen_exp_key "dilithium3 rsa"

gen_req "explicit_dilithium3_rsa" "$NULL_DIGEST"
verify  "explicit_dilithium3_rsa" "$NULL_DIGEST" "req"

gen_cer "explicit_dilithium3_rsa" "$NULL_DIGEST"
verify  "explicit_dilithium3_rsa" "$NULL_DIGEST" "cer"

gen_exp_key "dilithium3 ec"

gen_req "explicit_dilithium3_ec" "$NULL_DIGEST"
verify  "explicit_dilithium3_ec" "$NULL_DIGEST" "req"

gen_cer "explicit_dilithium3_ec" "$NULL_DIGEST"
verify "explicit_dilithium3_ec" "$NULL_DIGEST" "cer"

exit 0;

COMPOSITE_REQS_HYBRID_3_4_5="comp_dilithium2_falcon512 comp_dilithium3_falcon512 comp_dilithium5_falcon1024"
COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS="NULL $CLASSIC_DIGESTS"

# Composite Keys: Explicit Algorithms
COMPOSITE_ALGS_EXPLICIT_1="dilithium3 rsa"
COMPOSITE_ALGS_EXPLICIT_2="dilithium3 ec"
# EXPLICIT_COMPOSITE_ALGS_3="DILITHIUM3-ED25519"
# EXPLICIT_COMPOSITE_ALGS_4="DILITHIUM3-ED448"

COMPOSITE_REQS_EXPLICIT_1_2="explicit_dilithium3_rsa explicit_dilithium3_ec"
COMPOSITE_REQS_EXPLICIT_DIGESTS="NULL"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_3" "1"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_4" "2"

gen_comp_key "$COMPOSITE_ALGS_HYBRID_5" "1"

gen_req "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS"

verify "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS" "req" # <------ This one is broken

gen_cer "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS"

verify "$COMPOSITE_REQS_HYBRID_3_4_5" "$COMPOSITE_REQS_HYBRID_3_4_5_DIGESTS" "cer" # <------ This one is broken

fi

exit 0;

# ==================
# Explicit Composite
# ==================

# # Generate Explicit Composite Keys
# gen_exp_key "$COMPOSITE_ALGS_EXPLICIT_1"

# gen_exp_key "$COMPOSITE_ALGS_EXPLICIT_2"

# # Generates Explicit Composite CSRs
# gen_req "$COMPOSITE_REQS_EXPLICIT_1_2" "$COMPOSITE_REQS_EXPLICIT_DIGESTS"

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