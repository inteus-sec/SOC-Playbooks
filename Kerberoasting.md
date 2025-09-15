# Kerberoasting — Detection & Response (MITRE ATT&CK T1558.003)

## Purpose
Detect and respond to suspicious surges of Kerberos **TGS** requests for SPN-backed accounts, especially when tickets use **RC4 (0x17)**. Minimize false positives. Harden AD to reduce exposure.

---

## TL;DR (for L1)
- **Signal:** Many `4769` from one host/IP → many different **SPNs** → **TargetUserName** not ending with `$` → **TicketEncryptionType = 0x17 (RC4)**.
- **Correlate:** After TGS burst, watch for successful `4624` using the targeted service account.
- **Action:** Isolate the source, review impacted service accounts, force password rotation and AES-only, consider gMSA.

---

## Requirements
- Windows Security auditing on DCs with **Audit Kerberos Service Ticket Operations** enabled.
- Forwarded DC logs to SIEM.
- Time sync and host identity in logs (ClientAddress, Computer).

---

## Log sources
- **Windows Security (Domain Controllers)**
  - **4769**: *A Kerberos service ticket was requested*  
    Fields: `ServiceName (SPN)`, `TicketEncryptionType`, `ClientAddress`, `AccountName` (requestor), `TargetUserName` (service account), `Status/ResultCode`.
  - **4624/4625**: Successful/failed logons for post-TGS correlation.
  - **4648**: Explicit credentials usage (optional).
- **Directory data**: Inventory of accounts with `servicePrincipalName`.
- **EDR/Proxy/VPN/DNS**: Context of the requesting host and egress.

> Note: Encryption codes commonly seen: **0x17 = RC4-HMAC**, **0x11 = AES128**, **0x12 = AES256**. Focus RC4 but do not assume attacks cannot use AES.

---

## Heuristics
- **H1. Burst:** High `dcount(ServiceName)` for a single `ClientAddress`/host within 5–15 minutes.
- **H2. Weak crypto:** `TicketEncryptionType == 0x17` for `TargetUserName` **not** ending with `$`.
- **H3. Novelty:** New or rare SPNs for the given user/host versus a 14-day baseline.
- **H4. No use:** TGS burst without subsequent service usage (no network flows to the SPN service).
- **H5. Unusual origin:** Requests originate from endpoints that normally do not request service tickets.

**Common FP sources:** SSO proxies, monitoring/orchestration, backup controllers, discovery tools, vulnerability scanners, inventory scripts.

---

## MITRE ATT&CK
- **Technique:** T1558.003 Kerberoasting
- **Tactic:** Credential Access
- **Related:** T1558.001 (Golden Ticket, distinct signals), T1110.003 (Password Spraying context)

---

## Field mapping notes (adjust to your environment)
- Splunk: fields may appear as `Ticket_Encryption_Type` or `TicketEncryptionType`; `Service_Name` or `ServiceName`; `Client_Address` or `ClientAddress`; `Account_Name` or `AccountName`; `Target_User_Name` or `TargetUserName`.  
- Sentinel (KQL): `SecurityEvent` with `EventID`, `ServiceName`, `TicketEncryptionType`, `ClientAddress`, `Account`, `TargetUserName`, `Computer`.

---

## Splunk SPL — detections

### 1) TGS burst + RC4 + non-computer targets
```spl
index=wineventlog EventCode=4769
| eval TicketEnc=coalesce(Ticket_Encryption_Type, TicketEncryptionType)
| eval Service=coalesce(Service_Name, ServiceName)
| eval SrcIP=coalesce(Client_Address, ClientAddress, src_ip)
| eval Req=coalesce(Account_Name, AccountName)
| eval Tgt=coalesce(Target_User_Name, TargetUserName)
| where NOT like(Tgt,"%$")   /* exclude machine accounts */
| stats count dc(Service) AS d_spn values(TicketEnc) AS etypes BY SrcIP, host, Req
| where d_spn >= 10 OR (d_spn >= 3 AND mvfind(etypes,"0x17")>=0)
| sort - d_spn
