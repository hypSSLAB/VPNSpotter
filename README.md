# VPNSpotter
VPNSpotter is a lightweight VPN protocol identification tool that does not rely on AI.

It is based on the paper, "Practical VPN Fingerprinting using Coarse Inference of Field Specifications in Data Channels". 

## Environment & Setup
VPNSpotter has been built and tested on Ubuntu 22.04.

Before building VPNSpotter, you need to install the following dependencies:

```bash
sudo apt install build-essential libpcap-dev
``` 

## build
To build VPNSpotter, just run 'make' from the root directory of the project:
```bash
make
```

If the 'vpnspotter' executable file is generated, the build was successful.

## How to Use
To use VPNSpotter, run the 'vpnspotter' with a packet capture file (pcap) as an argument:
```bash
./vpnspotter -input=./sample_trace/OpenVPN_UDP.pcapng
```

The tool will output the inferred field specifications of the given network traffic, for example
```
S S S S S S S I R R R R R R R R R R R R R R R R
```

You can identify the VPN protocol by comparing these inferred specifications against the pre-built VPN protocol database. A sample database is available at ./field_specification_db/vpn.txt

## Tips & Notes

<details>
<summary>Click to expand additional tips and tools</summary>

### 1. Splitting into Single Session Traces
VPNSpotter takes a single-session PCAP file as an argument. To quickly split network traffic into individual sessions, we recommend using SplitCap ([Link](https://www.netresec.com/?page=SplitCap)).

### 2. Using the Other Classifier
For comparison with VPNSpotter, we have implemented a OpenVPN-specific classifier (ACK & Opcode-based) introduced by Xue et al. (USENIX Security 2022).

To build this classifier, modify the Makefile as follows:

```diff
# Line 12
- EXCLUDE_SOURCES = openvpn_fingerprint #vpnspotter
+ EXCLUDE_SOURCES = # openvpn_fingerprint vpnspotter
```

Then, run the make command again. If the 'openvpn_fingerprint' executable file is generated, the build was successful.

To use this classifier, run the 'openvpn_fingerprint' as follows:
```bash
./openvpn_fingerprint ./sample_trace/OpenVPN_UDP.pcapng ack (or opcode)
```
