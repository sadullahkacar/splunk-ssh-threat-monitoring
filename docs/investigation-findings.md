# SSH Authentication Threat Investigation

## Executive Summary

A hands-on SOC investigation was conducted using Linux SSH authentication logs ingested into Splunk.

The investigation identified sustained high-volume failed SSH authentication activity originating from multiple source IP addresses. Analysis included source IP profiling, account-targeting analysis, behavioral baselining, failed-to-successful authentication correlation, detection engineering, dashboard development, and scheduled alerting.

The dataset contained **25,099 failed SSH authentication attempts** originating from **185 source IP addresses** across three monitored hosts.

The available authentication telemetry identified activity consistent with automated SSH credential-guessing and account-enumeration behavior. However, the investigation did not establish evidence confirming successful unauthorized access.

---

## 1. Initial Data Assessment

The available Splunk data was first reviewed by index, sourcetype, source, and host.

The SSH investigation focused on:

```text
Index: security
Sourcetype: linux_secure
Source: secure.log
Hosts: web1, web2, web3
```

The security dataset contained **30,259 events**.

A search for failed SSH password authentication identified:

```text
25,099 failed authentication events
```

---

## 2. SSH Field Extraction

Relevant fields were extracted from the raw SSH authentication events using Splunk's `rex` command.

Extracted fields included:

- Source IP address
- Username
- Source port
- Authentication result
- Invalid-user indicator
- Destination host

Example event structure:

```text
Failed password for invalid user <username> from <source_ip> port <port> ssh2
```

This allowed the raw authentication events to be transformed into structured data suitable for statistical analysis and correlation.

---

## 3. Source IP Profiling

Failed authentication activity was aggregated by source IP.

For each source, the investigation measured:

- Total failed authentication attempts
- Number of unique accounts targeted
- Number of hosts targeted
- Invalid-account attempts
- Recognized-or-existing account attempts
- First observed activity
- Last observed activity
- Duration of observed activity

The highest-volume source IP in the dataset was:

```text
87.194.216.51
```

Observed activity:

| Metric | Result |
|---|---:|
| Failed authentication attempts | 730 |
| Unique accounts targeted | 137 |
| Targeted hosts | 3 |
| Invalid-account attempts | 531 |
| Recognized-or-existing account attempts | 199 |
| Invalid-account percentage | 72.74% |
| Observed duration | 168 hours |

The source targeted all three monitored systems:

```text
web1
web2
web3
```

The high authentication volume and broad username targeting were consistent with automated credential-guessing and account-enumeration behavior.

---

## 4. All-Time Behavioral Baseline

A behavioral baseline was calculated across all source IP profiles.

### Failed Authentication Attempts

| Metric | Result |
|---|---:|
| Minimum | 12 |
| Median | 124 |
| Average | ~135.67 |
| 95th percentile | ~217.6 |
| Maximum | 730 |

### Unique Accounts Targeted

| Metric | Result |
|---|---:|
| Median | 68 |
| Average | ~68.37 |
| 95th percentile | ~94.8 |
| Maximum | 137 |

The 95th-percentile values were rounded to:

```text
218 failed attempts
95 unique accounts
```

These values were used during the initial investigation to identify unusually active source IPs.

They were not used as universal production thresholds.

---

## 5. Failed-to-Successful Authentication Correlation

The investigation searched for authentication sequences where the same:

```text
source IP
+
username
+
host
```

generated failed authentication attempts followed by a successful authentication.

The correlation required the successful authentication to occur after the first observed failure.

### Result

```text
0 matching sequences
```

No failed-to-successful authentication sequence meeting these strict correlation conditions was identified.

This result does **not** establish that no compromise occurred.

A broader compromise assessment would require additional telemetry such as endpoint activity, network telemetry, process execution, session activity, and threat-intelligence enrichment.

---

## 6. Hourly Behavioral Baseline

To create a detection suitable for recurring monitoring, authentication behavior was recalculated using one-hour source-IP windows.

The analysis produced **1,137 source-IP/hour profiles**.

### Failed Attempts per Source IP per Hour

| Metric | Result |
|---|---:|
| Minimum | 1 |
| Median | 18 |
| Average | ~22.07 |
| 95th percentile | ~51.20 |
| Maximum | 148 |

### Unique Accounts per Source IP per Hour

| Metric | Result |
|---|---:|
| Median | 16 |
| Average | ~18.13 |
| 95th percentile | ~39.22 |
| Maximum | 80 |

The observed P95 values were rounded upward:

```text
Failed attempts: 51.20 → 52
Unique accounts: 39.22 → 40
```

These values became the primary thresholds for the hourly lab detection.

---

## 7. Detection Logic

A source IP is included in the detection when:

```text
failed_attempts >= 52
OR
unique_accounts >= 40
```

Detection reasons are assigned according to the observed behavior:

```text
High failures + broad account targeting
High failure volume
Broad account targeting
```

Severity classification was added to assist analyst triage.

The `Critical` threshold used in this lab represents additional detection tuning and was not derived directly from the P95 calculation.

The final detection returned:

```text
64 source-IP/hour detection results
```

The highest observed detection included:

| Field | Result |
|---|---|
| Source IP | 87.194.216.51 |
| Severity | Critical |
| Failed attempts | 148 |
| Unique accounts | 80 |
| Targeted hosts | 3 |
| Detection reason | High failures + broad account targeting |

---

## 8. Dashboard Development

A Splunk dashboard was created to provide analysts with both high-level monitoring and investigation context.

The dashboard contains visualizations for:

- Top source IPs by failed SSH attempts
- Most targeted SSH accounts
- Failed SSH attempts by host
- Suspicious source IP count
- Invalid vs. recognized SSH account attempts
- Failed SSH attempts over time
- Hourly high-risk SSH activity
- Detailed suspicious source IP investigation results

This provides both summary-level monitoring and detailed analyst investigation capability from the same dashboard.

---

## 9. Scheduled Alert

The final hourly detection was operationalized as a Splunk scheduled alert.

Configuration:

```text
Alert: SSH High-Risk Authentication Activity
Status: Enabled
Schedule: Hourly
Trigger: Number of Results > 0
Action: Add to Triggered Alerts
```

The scheduled search used a delayed time window to account for potential ingestion latency.

This completed the workflow from investigation to recurring detection and alerting.

---

## 10. Analyst Assessment

The observed activity is consistent with automated SSH credential-guessing and account-enumeration behavior due to:

- High authentication failure volume
- Broad username targeting
- Repeated activity across multiple hosts
- Significant targeting of usernames identified by the SSH logs as invalid

The available authentication logs do not provide sufficient evidence to confirm successful unauthorized access.

Additional endpoint, network, identity, and threat-intelligence telemetry would be required to determine whether any observed source resulted in unauthorized access.

---

## 11. Recommended SOC Actions

If similar activity were detected in a production environment, the next investigation steps would include:

1. Enrich suspicious source IPs using approved threat-intelligence and OSINT sources.
2. Search the same source IPs across additional security telemetry.
3. Review successful SSH authentication involving the targeted infrastructure.
4. Investigate endpoint and process activity following suspicious successful logins.
5. Determine whether targeted accounts are privileged, administrative, service, or expected accounts.
6. Determine whether the sources belong to approved scanners, vendors, VPN infrastructure, or other authorized systems.
7. Consider blocking, rate limiting, or other controls with the appropriate security and infrastructure teams.

---

## Conclusion

This investigation demonstrated an end-to-end SOC workflow using Splunk:

```text
Log Review
    ↓
Field Extraction
    ↓
Source IP Profiling
    ↓
Behavioral Baseline
    ↓
Authentication Correlation
    ↓
Detection Engineering
    ↓
Dashboard Development
    ↓
Scheduled Alerting
    ↓
Analyst Assessment
```

The project demonstrates how raw authentication telemetry can be transformed into a repeatable detection and monitoring workflow while maintaining appropriate limitations around what the available evidence can establish.
