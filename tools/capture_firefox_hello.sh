#!/bin/bash
set -euo pipefail

TARGET="${1:-www.google.com}"
PCAP_FILE="/tmp/firefox_hello_$$.pcap"
HEX_FILE="/tmp/client_hello_$$.hex"

echo "Starting capture; manually open Firefox and visit https://${TARGET}, then press Enter..."
read -r _

echo "Capturing TLS ClientHello to ${TARGET}:443 ..."
sudo tcpdump -i any -c 1 -w "${PCAP_FILE}" \
    "tcp port 443 and host ${TARGET}" 2>/dev/null || {
    echo "Capture failed (try running with sudo)"
    exit 1
}

echo "Extracting ClientHello hex..."
tshark -r "${PCAP_FILE}" \
    -T fields -e tls.handshake.ja3 \
    -e tls.handshake.ja3_full \
    -Y "tls.handshake.type == 1" 2>/dev/null | head -1 > /tmp/ja3_info.txt

JA3=$(cut -f1 /tmp/ja3_info.txt)
echo "JA3: ${JA3}"

tshark -r "${PCAP_FILE}" \
    -T fields -e tls.record.layer_data \
    -Y "tls.handshake.type == 1" 2>/dev/null | tr -d '\n' | tr -d ':' > "${HEX_FILE}"

BYTE_COUNT=$(wc -c < "${HEX_FILE}")
echo "ClientHello saved to ${HEX_FILE} (${BYTE_COUNT} hex chars)"
echo "Run: KANOTLS_CLIENT_HELLO_PATH=${HEX_FILE} kanotls ..."

# Cleanup
rm -f "${PCAP_FILE}" /tmp/ja3_info.txt
