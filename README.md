# P4R: Scaling Stateful Network Testing and Trace Replay with Nanosecond-level Accuracy

**Abstract:** As network speeds transition to 100 Gbps and beyond, traditional software-based traffic generators face significant performance and accuracy bottlenecks due to CPU and PCIe limitations. P4R (P4 Replay) is an open-source framework designed for high-fidelity stateful network testing on programmable ASICs. P4R overcomes previous design constraints by introducing a dynamic window management system for TCP connections and a dual-mode trace replay engine capable of reproducing pre-captured PCAP files with nanosecond-level timing accuracy or user-defined throughput.

---

## Structure of the readme.md

This repository is organized as follows to facilitate the evaluation process:
1. **Considered Badges:** Evaluation claims and targeted badges.
2. **Basic Information:** Environment and hardware requirements.
3. **Dependencies:** Required libraries and packages.
4. **Security Concerns:** Warnings about execution permissions.
5. **Installation:** Initial setup steps.
6. **Minimal Test:** Execution in a simulated environment (Local PCAP translation).
7. **Experiments:** Execution in the real environment (Intel Tofino Switch).
8. **Team:** Developing team and contributors.
9. **License:** Usage license.

---

## Considered Badges

The badges considered for this artifact are:
* **Artifacts Available** (SeloD)
* **Artifacts Functional** (SeloF)
* **Artifacts Sustainable** (SeloS)
* **Reproducible Experiments** (SeloR)

*Note to reviewers: Due to the dependence on specific hardware (Intel Tofino Switch) for full trace replay at line-rate, we provide a local configuration parser for the Minimal Test. This ensures that reviewers can evaluate the PCAP translation functionality even without access to the physical switch.*

---

## Basic Information

P4R features two execution stages. The requirements vary depending on the chosen stage:

**1. Parsing Mode (Minimal Test):**
* **Hardware:** Any standard computer or virtual machine (1GB RAM and 1 CPU core are sufficient).
* **OS:** Linux (Tested on Ubuntu 18.04 / 20.04 / 22.04).

**2. Replay Mode (Full Experiment):**
* **Hardware:** A programmable switch based on the Intel Tofino ASIC.
* **OS (Switch):** Configured Intel SDE environment.

---

## Dependencies

**Software and Libraries (For both modes):**
* Python 3.6 or higher.
* Scapy (`pip3 install scapy`).

**Intel SDE (Only for Replay Mode):**
* SDE Version: Tested on `9.13.x` (compatible with `9.12.x`).

---

## Security Concerns

For the Python scripts to successfully process network configurations and for the SDE scripts to access hardware interfaces, **superuser (`sudo`) privileges are mandatory**. The provided scripts do not make any permanent changes to the file system beyond generating Python configuration files based on the input PCAPs.

---

## Installation

Open the terminal in your Linux environment and execute the following commands:
```bash
# Clone the repository
git clone https://github.com/intrig-unicamp/P4R.git
cd P4R

# Install Python dependencies
sudo apt-get update
sudo apt-get install python3-pip
sudo pip3 install scapy
```

---

## Minimal Test

To allow reviewers to observe the functionality of the P4R trace parser without requiring Tofino hardware, we provide a PCAP translation script. This script acts as the first stage of the P4R workflow.

**Step 1: Generate the Register Configuration**
P4R translates PCAP files into specific register entries to store the packet content directly on the switch memory. Run the generation script using the provided example PCAP (`testing.pcap`):
```bash
python3 generateFiles.py testing.pcap
```

*Expected Result:* The script will successfully parse the PCAP and generate a new file named `configuration_file.py`. This auto-generated file translates the PCAP packets into Tofino register insertions, systematically loading packet sizes, timestamps, and payload values into pipeline structures. If you open the file, you will be able to see each of the packets of the pcap, translated in register entries like below:
```bash
#packet0: 
storage1.add(REGISTER_INDEX=0, f1=0x001b21a0)
storage2.add(REGISTER_INDEX=0, f1=0x52d4ac1f)
...
time.add(REGISTER_INDEX=0, f1=0)


#packet1: 
storage1.add(REGISTER_INDEX=1, f1=0xac1f6b67)
...
time.add(REGISTER_INDEX=1, f1=148000)


#packet2: 
storage1.add(REGISTER_INDEX=2, f1=0x001b21a0)
...
time.add(REGISTER_INDEX=2, f1=68000)
```

Storage are the register that store the packet contents, and time is the register that store the time that the packet should be sent (if you are using the timer mode). This is the maximum step that you can do without a tofino switch. If you have access to a Tofino switch, then you can start the PCAP reproduction following the next steps.

---

## Experiments

This section describes the execution in the real environment (Intel Tofino Switch), allowing reviewers to validate the high-speed replay claims.

### Claim #1: Line-rate PCAP Reproduction

P4R is capable of reproducing pre-captured PCAP files at line-rate (maximum possible throughput) directly from the switch's data plane, leveraging a throughput-mode trace replay engine.

**Step 1: Switch Setup and Compilation**
1. Ensure your PCAP has been parsed into `configuration_file.py` (as done in the Minimal Test).
2. Edit the `portConfig.txt` file to properly match the physical ports available and connected in your specific Tofino hardware environment.
3. Set the required SDE bash environment variables in your terminal.
4. Compile the P4 code, load the table entries, and configure traffic generation by running:
```bash
./execut.sh
```

**Step 2: Start the Replay**
Once the switch has successfully initialized and the tables are fully loaded, open a **second terminal** on the switch (ensure the SDE environment variables are also set in this new terminal).

Start the PCAP reproduction by triggering the control script via `bfshell`:
```bash
/$SDE/run_bfshell.sh -b Start.py
```

*Expected Result:* The switch will begin replaying the `testing.pcap` trace in a continuous loop. The traffic will be generated entirely inside the ASIC and transmitted out of the configured ports at the maximum possible hardware throughput.

---

## Team

* Francisco Germano Vogt
* Leonardo Henrique Guimaraes
* Zhiheng Yang
* Fabricio Eduardo Rodriguez Cesen
* Sergio Rossi Brito da Silva
* Marcelo Caggiani Luielli
* Chrysa Papagianni
* Christian Esteve Rothenberg


## LICENSE

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
