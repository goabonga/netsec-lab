# PCAP forensics

## 1. Context & stakes

Reconstruct an attack from a capture (blue-team exercise).

A packet capture is ground truth: from the pcap an analyst reconstructs who talked to whom, what was exfiltrated, and which credentials crossed the wire in the clear. The skill is turning raw frames back into an incident timeline. Cleartext protocols like FTP, HTTP Basic and plain LDAP still leak passwords that a single captured pcap hands to an attacker, or in a breach investigation to the responder.

## 2. How it works

A packet capture is ground truth. Forensics reconstructs an incident from a pcap - following flows, extracting objects, correlating timing - to build the attack timeline. This module reads plain records from a capture and surfaces indicators: top talkers, a packet/talker summary, and any credential that crossed the wire in cleartext.

## 3. Commands

```bash
netlab-pcap-forensics brief                   # teaching brief
netlab-pcap-forensics detect --pcap capture.pcap  # triage a real capture
netlab-pcap-forensics defend                  # triage a synthetic capture
```

## 4. What it detects

`detect` reads the pcap with scapy and reports every cleartext credential
(`PASS `, `password=`, HTTP Basic `Authorization`) plus a summary. `defend` runs
the same analyser on a synthetic capture that leaks an FTP and an HTTP Basic
password:

```
[!!] ALERT     cleartext credential 10.0.0.5 -> 10.0.0.9:21
[!!] ALERT     cleartext credential 10.0.0.7 -> 10.0.0.9:80
[..] INFO      packets=3 talkers=2 leaks=2
```

Each leak is a `src -> dst:dport` you can pivot on: the port names the protocol
(21 = FTP, 80 = HTTP Basic), the endpoints anchor the timeline.

## 5. Operating it

- Capture with `tcpdump -w capture.pcap` off a SPAN/TAP port, then analyse
  offline - forensics never runs on the live wire.
- Escalate any cleartext credential to a rotation and a push to encrypted
  protocols (FTPS/SFTP, HTTPS, LDAPS).
- Feed the same capture to [`netlab-ids`](ids.md) to correlate a signature hit
  with the reconstructed timeline.

## 6. Further reading

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html/) (`tshark`)
- C. Sanders, Practical Packet Analysis
