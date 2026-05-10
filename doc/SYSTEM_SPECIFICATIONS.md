# P4R: Artifacts and Configuration Guide

This document provides a detailed description of the P4R project files and the mandatory hardware configuration steps for the Intel Tofino ASIC.

---

## 1. Project Structure and File Descriptions

The following table summarizes each component of the P4R framework.

| File | Type | Description |
| :--- | :--- | :--- |
| **`generateFiles.py`** | Python Script | CLI tool that parses an input PCAP to generate the BFRT configuration script. |
| **`execut.sh`** | Bash Script | Automates P4 compilation, driver initialization, and hardware configuration. |
| **`configuration_file.py`** | BFRT Script | **(Auto-generated)** Populates registers with packet data and nanosecond-level timestamps. |
| **`reproPCAP.p4`** | P4 Source | Main P4-16 program containing the trace replay pipeline logic. |
| **`headers.p4`** | P4 Header | Standard protocol header definitions (Ethernet, IPv4, TCP, UDP). |
| **`portConfig.txt`** | Config File | Mandatory file for initializing and enabling physical Tofino ports. |
| **`Start.py`** | BFRT Script | Trigger script that starts the packet reproduction in the data plane. |
| **`tableEntries.py`** | BFRT Script | Defines match-action table entries for packet templates and recirculation. |
| **`view`** | CLI Script | Helper file to monitor real-time throughput and port statistics. |

---

## 2. Port Configuration (`portConfig.txt`)

The `portConfig.txt` file is essential for hardware communication. It must contain the mandatory configuration for **Port 5**, followed by any additional ports required by the user's environment.

### Mandatory File Content
The file must interact with the Unit Command Line Interface (`ucli`) and Port Manager (`pm`). The following block for **Port 5** is essential and must be present:

```bash
ucli
pm

# **** ESSENTIAL SYSTEM PORTS ****
# Mandatory configuration for Port 5 (100G, no FEC)
port-add 5/- 100G NONE
port-enb 5/-

# Force speed and disable autonegotiation
an-set 5/- 2 

# Toggle port status to finalize setup
port-dis 5/-
port-enb 5/-

# (Optional) Enable MAC-near loopback for local testing
port-loopback 5/- mac-near

# **** USER PORTS ****
# Users can define additional ports below following the same sequence:
# port-add {PORT}/{CHANNEL} {BANDWIDTH} NONE
# ...

show
exit
exit