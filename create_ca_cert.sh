#! /bin/bash

set -Eeuo pipefail

# Default values
CERT_PASSWORD=${CERT_PASSWORD:-foobar} # Allow override via environment
KEY_SIZE_CA=${KEY_SIZE_CA:-4096}
KEY_SIZE_WEB=${KEY_SIZE_WEB:-2048}
ENCRYPTION_CIPHER="des3"
ALLDOMAINS=${ALLDOMAINS:-""}

# Cleanup function
cleanup() {
	local exit_code=$?
	# Clean up temporary files if any
	rm -f *.tmp 2>/dev/null
	exit $exit_code
}

trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit -1' INT PIPE TERM

# Enhanced logging
logInfo() {
	echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

logError() {
	echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

# Create directory with proper permissions
create_secure_dir() {
	local dir=$1
	mkdir -p "$dir"
	chmod 700 "$dir"
}

# Generate key with proper permissions
generate_secure_key() {
	local keyfile=$1
	local keysize=$2
	openssl genrsa -${ENCRYPTION_CIPHER} -passout "pass:${CERT_PASSWORD}" -out "$keyfile" "$keysize" &>/dev/null
	chmod 600 "$keyfile"
}

# Main script starts here

PROJ_NAME=DockerMirrorBox
logInfo "Will create certificate with names $ALLDOMAINS"

CADATE=$(date "+%Y.%m.%d %H:%M")
CAID="$(hostname -f) ${CADATE}"

CN_CA="${PROJ_NAME} CA Root ${CAID}"
CN_IA="${PROJ_NAME} Intermediate IA ${CAID}"
CN_WEB="${PROJ_NAME} Web Cert ${CAID}"

CN_CA=${CN_CA:0:64}
CN_IA=${CN_IA:0:64}
CN_WEB=${CN_WEB:0:64}

mkdir -p /certs ca
cd /ca

CA_KEY_FILE=${CA_KEY_FILE:-/ca/ca.key}
CA_CRT_FILE=${CA_CRT_FILE:-/ca/ca.crt}
CA_SRL_FILE=${CA_SRL_FILE:-/ca/ca.srl}

if [ -f "$CA_CRT_FILE" ]; then
	logInfo "CA already exists. Good. We'll reuse it."
	if [ ! -f "$CA_SRL_FILE" ]; then
		echo 01 >"${CA_SRL_FILE}"
	fi
else
	logInfo "No CA was found. Generating one."
	logInfo "*** Please *** make sure to mount /ca as a volume -- if not, everytime this container starts, it will regenerate the CA and nothing will work."

	create_secure_dir "/ca"
	generate_secure_key "${CA_KEY_FILE}" "${KEY_SIZE_CA}"

	logInfo "generate CA cert with key and self sign it: ${CAID}"
	openssl req -new -x509 -days 36500 -sha256 -key "${CA_KEY_FILE}" -out "${CA_CRT_FILE}" -passin pass:foobar -subj "/C=DE/ST=Schleswig-Holstein/L=Kiel/O=Gitpod GmbH/OU=IT/CN=${CN_CA}" -extensions IA -config <(
		cat <<-EOF
			[req]
			distinguished_name = dn
			[dn]
			[IA]
			basicConstraints = critical,CA:TRUE
			keyUsage = critical, digitalSignature, cRLSign, keyCertSign
			subjectKeyIdentifier = hash
		EOF
	)

	echo 01 >"${CA_SRL_FILE}"

fi

cd /certs

logInfo "Generate IA key"
openssl genrsa -des3 -passout pass:foobar -out ia.key 4096 &>/dev/null

logInfo "Create a signing request for the IA: ${CAID}"
openssl req -new -key ia.key -out ia.csr -passin pass:foobar -subj "/C=DE/ST=Schleswig-Holstein/L=Kiel/O=Gitpod GmbH/OU=IT/CN=${CN_IA}" -reqexts IA -config <(
	cat <<-EOF
		[req]
		distinguished_name = dn
		[dn]
		[IA]
		basicConstraints = critical,CA:TRUE,pathlen:0
		keyUsage = critical, digitalSignature, cRLSign, keyCertSign
		subjectKeyIdentifier = hash
	EOF
)

logInfo "Sign the IA request with the CA cert and key, producing the IA cert"
openssl x509 -req -days 36500 -in ia.csr -CA "${CA_CRT_FILE}" -CAkey "${CA_KEY_FILE}" -CAserial "${CA_SRL_FILE}" -out ia.crt -passin pass:foobar -extensions IA -extfile <(
	cat <<-EOF
		[req]
		distinguished_name = dn
		[dn]
		[IA]
		basicConstraints = critical,CA:TRUE,pathlen:0
		keyUsage = critical, digitalSignature, cRLSign, keyCertSign
		subjectKeyIdentifier = hash
	EOF
) &>/dev/null

logInfo "Initialize the serial number for signed certificates"
echo 01 >ia.srl

logInfo "Create the key (w/o passphrase..)"
openssl genrsa -des3 -passout pass:foobar -out web.orig.key 2048 &>/dev/null
openssl rsa -passin pass:foobar -in web.orig.key -out web.key &>/dev/null

logInfo "Create the signing request, using extensions"
openssl req -new -key web.key -sha256 -out web.csr -passin pass:foobar -subj "/C=DE/ST=Schleswig-Holstein/L=Kiel/O=Gitpod GmbH/OU=IT/CN=${CN_WEB}" -reqexts SAN -config <(cat <(printf "[req]\ndistinguished_name = dn\n[dn]\n[SAN]\nsubjectAltName=%s" "$ALLDOMAINS"))

logInfo "Sign the request, using the intermediate cert and key"
openssl x509 -req -days 36500 -in web.csr -CA ia.crt -CAkey ia.key -out web.crt -passin pass:foobar -extensions SAN -extfile <(cat <(printf '[req]\ndistinguished_name = dn\n[dn]\n[SAN]\nsubjectAltName=%s' "$ALLDOMAINS")) &>/dev/null

logInfo "Concatenating fullchain.pem..."
cat web.crt ia.crt "${CA_CRT_FILE}" >fullchain.pem

logInfo "Concatenating fullchain_with_key.pem"
cat fullchain.pem web.key >fullchain_with_key.pem

# Secure the generated files
chmod 600 /certs/*.key
chmod 644 /certs/*.crt /certs/*.pem

logInfo "Certificate generation completed successfully"
