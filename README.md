<div align="center">

# RDP CHECKER
### DHTOOLS terminal skin

**Authorized Windows host reachability monitor**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux-0d1117?style=flat-square&logo=linux&logoColor=white)](#)
[![Purpose](https://img.shields.io/badge/Purpose-Reachability%20Monitoring-0d1117?style=flat-square)](#)

</div>

---

## About

A small terminal-oriented project for checking the network reachability of
Windows hosts in an environment you own or are explicitly authorized to test.

This README describes a **reachability-only** workflow. It does not document
credential testing, password spraying, remote command execution, or attempts
to conceal which connection method was used.

> Never put passwords, access tokens, or other secrets in a target list,
> source file, terminal transcript, or generated report.

## Features

- Checks whether configured hosts are reachable.
- Produces a concise, human-readable status report.
- Keeps generated output in one clearly named report file.
- Uses plain ASCII status labels for compatibility with terminals and logs.

## Project Structure

```text
.
├── rdp.py       # Reachability checker
├── a.txt               # IP addresses (ip:user:pass)
├── banner.txt          # Generated report
├── requirements.txt    # Python dependencies, if required
└── README.md
```

## Input Format

`a.txt` contains one IP address per line.

```text
# Example documentation values only
192.0.2.10:administrator:passs
198.51.100.20:administrator:passs224
```

Blank lines and lines beginning with `#` may be ignored.

The addresses above are reserved for documentation and are not real target
systems. Do not add usernames or passwords to this file.

## Status Labels

| Mark | Meaning |
|---|---|
| `[Reachable]` | The host responded to the configured network check. |
| `[Unreachable]` | No response was received within the configured timeout. |
| `[Error]` | The check could not be completed; inspect the local error log. |

A reachable host is **not** proof that a remote login is possible or that
a user account is valid.

## Setup

Use a virtual environment to keep project dependencies isolated.

```bash
sudo apt update
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
```

If the project has a `requirements.txt` file:

```bash
python -m pip install -r requirements.txt
```

## Running

After reviewing the source and confirming that the target list contains only
systems you are authorized to assess:

```bash
source .venv/bin/activate
python3 rdp.py.py
```

The expected report location is `banner.txt`, if configured by the program.

## Reporting and Secret Handling

- Do not include passwords or other credentials in reports.
- Restrict access to generated reports because host inventories can be sensitive.
- Redact internal addresses and hostnames before publishing screenshots or logs.
- Store secrets in an approved secret manager; do not hard-code them.
- Keep an audit trail of authorized testing and its scope.

## Troubleshooting

| Symptom | Suggested check |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and install the listed dependencies. |
| No hosts respond | Verify the target list, routing, firewall rules, and timeout settings. |
| Report is missing | Check the program output and configured report path. |
| Garbled terminal output | Save source files as UTF-8 and use a compatible terminal. |

## Disclaimer

Use this project only on systems you own or have explicit permission to assess.
Follow your organization's security policy and applicable laws. Do not use it
to test credentials against third-party systems or to access systems without
authorization.

---

<div align="center">

**MADE IN DHTOOLS — FROM #**

*Build it. Understand it. Rebuild it better.*

</div>
