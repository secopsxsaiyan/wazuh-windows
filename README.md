# Windows Endpoint Rules for Wazuh

Escalate two classes of Windows endpoint activity that stock Wazuh leaves below a triage gate:
**VPN/tunnel-client service installs** and **WSL (Windows Subsystem for Linux) activity**.

Authored after a pentest-visibility audit: a Windows lab host generated **no** process-execution
telemetry (no Sysmon, no EventID 4688), and its OpenVPN + WSL installs fired only stock rule
`61138` at **L5** — below the L10 triage gate. These rules re-rate that activity to **L10**.

> **Home-grown** — not part of the stock Wazuh ruleset. Companion packs:
> [wazuh-threat-detection](https://github.com/secopsxsaiyan/wazuh-threat-detection),
> [wazuh-fim-escalation](https://github.com/secopsxsaiyan/wazuh-fim-escalation),
> [wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc).

## Layout

```
custom_rules/windows_rules.xml   # children of stock 61138 (EventID 7045) and the sysmon_event1 group
```

## Rules

| ID | Level | Detects | Source event | MITRE | Status |
|----|-------|---------|--------------|-------|--------|
| 100450 | 10 | VPN tunnel-client service installed (OpenVPN / TAP-Windows / WireGuard) | EventID **7045** → stock 61138 | T1572 | active |
| 100451 | 10 | WSL / Linux-subsystem service installed | EventID **7045** → stock 61138 | T1202 | active |
| 100452 | 10 | WSL **execution** (`wsl.exe` / `wslservice` / `bash.exe`) | Sysmon **EventID 1** | T1202, T1059.004 | **dormant** |

### Why these matter
- **Tunnel clients** (100450) on a managed endpoint frequently precede C2 / exfil over an
  encrypted tunnel that bypasses inline inspection.
- **WSL** (100451/100452) spins up a full Linux execution environment that the **Windows** Wazuh
  agent cannot see inside — an `nmap`/`hydra`/`gobuster` run under WSL is invisible to the host
  agent, so the *creation* and *use* of WSL is itself the signal.

## Requirements

- **100450 / 100451** need the **System** event channel (EventID 7045, service installs), which a
  default Windows Wazuh agent already collects via `61138`. No extra config.
- **100452 is dormant** until you collect **Sysmon EventID 1** (process creation): deploy Sysmon
  to the endpoint and add the channel to the agent `ossec.conf`:

  ```xml
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  ```

  Then validate against a real WSL launch (see "Verify" below).

## Install

```bash
cp custom_rules/windows_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/windows_rules.xml
chmod 0644 /var/ossec/etc/rules/windows_rules.xml

# confirm the 100450-100452 range is free (expect empty):
grep -rhoE --exclude=windows_rules.xml 'rule id="10045[0-2]"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/

/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-control restart   # or `up -d --force-recreate` for single-file bind mounts
```

## Verify

Windows event-channel events are decoded by Wazuh's built-in `windows_eventchannel` decoder,
which only runs for events that arrive from an agent's `eventchannel` log collector — pasting
the JSON into `wazuh-logtest` decodes it as plain `json` and never reaches rule `60000`/`61138`.
Test on a real endpoint instead:

- **100450** — install (or reinstall) an OpenVPN / WireGuard client.
- **100451** — `wsl --install` (or enable the "Windows Subsystem for Linux" feature).
- **100452** — with Sysmon deployed, run `wsl.exe` (or `bash.exe`).

Each should appear in the alerts at level 10; other new services still alert as stock `61138` (L5).

## ID range / collisions

Uses **100450-100452** — clear of stock Wazuh and the other secopsxsaiyan packs. Verify it is also free on your manager before installing.

## License

MIT — see [LICENSE](LICENSE).
