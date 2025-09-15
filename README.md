# pcap2mermaid

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![scapy](https://img.shields.io/badge/scapy-GPL%20v2%2B-blue)](https://github.com/secdev/scapy)

**pcap2mermaid** is a Python tool that converts SIP traffic from a PCAP capture into a [Mermaid](https://mermaid-js.github.io/mermaid/#/sequenceDiagram) sequence diagram, which you can use to visualize call flows.

This script is robust and feature-rich, supporting custom participant naming, SIP filtering, time annotation, summary tables, progress and error logging, and more.

---

## Features

- **SIP-over-UDP/TCP, IPv4/IPv6** supported
- **Custom participant naming** via mapping or CSV
- **Autonumbered diagrams** (Mermaid's `autonumber`)
- **SIP method/status filtering**
- **Timestamp annotations** (optional)
- **Summary mapping table** (optional)
- **Progress and dropped-packet logging**
- **Robust error handling**
- **Large file support**
- **Output to file or screen**: If you omit the output file argument, the diagram prints to your terminal (stdout).
- **Short or mapped participant names** with `--add-participants` (e.g. `A`, `B`, `C`)
- **SIP URI parameters (e.g. `;user=phone`) are omitted** from the sequence diagram for compatibility with Mermaid.
- **Option to hide participant boxes at the bottom** (`--no-bottom-actors`)
- **By default, only declares participants actually used in SIP messages** (diagram lines), **not all hosts/ports seen** (see below for `--all-participants`).

---

## Requirements

- Python 3.7+
- [scapy](https://pypi.org/project/scapy/) (`pip install scapy`)

---

## Usage

```sh
python3 pcap2mermaid.py input.pcap [output.md] [options]
```

- If `output.md` is omitted, the diagram is printed to the screen (stdout).

### Options

| Option                | Description                                                  |
|-----------------------|-------------------------------------------------------------|
| `--mapping`           | Comma-separated host:port=name (e.g. `1.2.3.4:5060=PBX,...`)|
| `--participant-names` | CSV file: `<ip>:<port>,name`                                |
| `--port`              | SIP port (default: 5060)                                    |
| `--add-participants`  | Add `participant` lines to diagram with short names (A, B, ...)|
| `--autonumber`        | Add Mermaid `autonumber` to sequence diagram                |
| `--filter-method`     | Comma-separated SIP methods to include (e.g. `INVITE,BYE`)  |
| `--filter-status`     | Comma-separated SIP status codes (e.g. `200,486`)           |
| `--add-time`          | Prepend timestamp to each message                           |
| `--summary-table`     | Output a participant mapping table at end of output         |
| `--no-skip-provisional`| Include provisional (<180) SIP responses                   |
| `--logfile`           | Write logs to a file                                        |
| `--verbose`           | Show debug log messages                                     |
| `--quiet`, `--silent` | Suppress informational log messages; only show errors       |
| `--no-bottom-actors`  | Hide the actor boxes (participants) at the bottom           |
| `--all-participants`  | Declare all seen participants, even if not shown in diagram |

---

### Example

#### Output to screen

```sh
python3 pcap2mermaid.py calls.pcap --add-participants --autonumber
```

#### Output to file

```sh
python3 pcap2mermaid.py calls.pcap calls.md --add-participants --autonumber
```

#### With participant mapping

```sh
python3 pcap2mermaid.py calls.pcap calls.md --mapping "10.0.0.1:5060=PBX,10.0.0.2:5060=Phone"
```

#### With custom participant CSV

Create a `names.csv`:
```
10.0.0.1:5060,PBX
10.0.0.2:5060,Phone
```

Then run:
```sh
python3 pcap2mermaid.py calls.pcap calls.md --participant-names names.csv --add-participants
```

#### With SIP method filtering and time annotation

```sh
python3 pcap2mermaid.py calls.pcap calls.md --filter-method INVITE,BYE --add-time
```

#### Hide bottom actors (participant boxes at the bottom):

```sh
python3 pcap2mermaid.py calls.pcap --add-participants --no-bottom-actors
```

#### Declare all seen participants (not just those used in diagram):

```sh
python3 pcap2mermaid.py calls.pcap --add-participants --all-participants
```

---

## Output Example

With `--add-participants --autonumber --no-bottom-actors`, the output will look like:

```mermaid
%%{init: { "sequence": { "mirrorActors": false } }}%%
sequenceDiagram
    autonumber
    participant A as 10.33.6.100:5060
    participant B as 10.33.6.101:5060
    B->>A: INVITE 101@10.33.6.100
    A-->>B: 180 (Ringing)
    A-->>B: 200 (OK)
    B->>A: ACK 101@10.33.6.100:5060
    A->>B: BYE 201@10.33.6.101:5060
    B-->>A: 200 (OK)
```

Notice:
- **No SIP URI parameters** (e.g., `;user=phone`) appear in the output, to ensure Mermaid compatibility.
- Short names (`A`, `B`, etc.) are used as participant labels.
- No blank lines or illegal characters in messages.
- The Mermaid `init` line disables the bottom row of actors.

You can paste this into [Mermaid Live Editor](https://mermaid.live/) or compatible markdown viewers.

---

## Tips

- For large PCAP files, consider filtering with `tcpdump` or Wireshark before processing.
- If you use `--add-participants`, you can easily change the participant names in the Mermaid file.
- Use `--summary-table` for quick mapping reference.
- If you encounter Mermaid parse errors, ensure your SIP URIs do not contain forbidden characters (the script omits parameters for you).

---

## License

[GNU General Public License v2.0 or later](LICENSE)

**Note:** This project uses [scapy](https://github.com/secdev/scapy), which is licensed under the GPL v2 or later. Therefore, this tool is also licensed under the GPL v2 or later.
