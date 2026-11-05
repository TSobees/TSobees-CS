# Nmap Network Inventory and Assessment

[![Project checks](https://github.com/TSobees/TSobees-CS/actions/workflows/checks.yml/badge.svg)](https://github.com/TSobees/TSobees-CS/actions/workflows/checks.yml)

An educational network-assessment record with a reusable **offline XML reporting
tool**. The tool reads saved Nmap output; it does not run a scanner or contact hosts.

## Generate an inventory

Python 3.12 or 3.13, no pip dependencies:

```sh
python -m network_report
python -m network_report path/to/scan.xml --output-dir outputs/review
```

The output directory receives `inventory.md`, `inventory.csv` and `summary.json`.
The bundled scan contains four up hosts and two individually listed open TCP ports.
JSON retains script results, omitted-port aggregates and OS guesses for review.

## Layout

```text
network_report/                 Offline parser and command-line report writer
data/scans/                     Original .xml, .nmap and .gnmap evidence
docs/reports/                   Original narrative assessment
docs/images/                    Original screenshots
docs/licensing/                 Preserved earlier license notice
tests/                         Bundled evidence and invalid-input checks
outputs/                       Generated reports, ignored by Git
```

The previous `scans/`, `report/` and `screenshots/` folders now live under the paths
above. Original evidence is retained. Read the [assessment](docs/reports/Network_Scan_Report.md)
alongside [raw output](data/scans/network_scan.nmap).

## Findings and limits

The saved January 2025 scan reports IIS on TCP 80, DNS on TCP 53, a TRACE method
observation, and hosts with filtered or closed ports. OS identifications are
inconclusive guesses under imperfect scan conditions. DNS NOTIMP responses and
unrecognized service fingerprints need investigation; they do not by themselves
establish a vulnerability. These are historical observations, not current host status.

The original report mixes example `192.168.1.0/24` commands with recorded
`192.168.204.128/24` scope. Treat the raw XML as the source for this scan; those
examples are not additional assessments. Only scan systems within an explicitly
authorized scope. The supplied reporting command needs neither root nor Nmap.

## Tests and references

```sh
python -m unittest discover -s tests -v
```

[Nmap XML documentation](https://nmap.org/book/output-formats-xml-output.html).
MIT license; existing notices are retained. Author: Sobanjo Oluwatosin.
AI assisted the offline tooling, evidence clarification, organization and tests.
