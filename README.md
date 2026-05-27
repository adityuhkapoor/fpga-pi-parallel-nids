# fpga-pi-parallel-nids

A Raspberry Pi sniffs packets and offloads classification to a Basys 3 FPGA over SPI.
For each IPv4 packet, the Pi extracts a fixed 20-byte header and sends it to the FPGA.
The FPGA checks the source and destination IP against a known-bad (C2) blocklist.
It does this with a Bloom filter and returns a per-packet verdict.
The Pi decodes the verdict: clean, or flagged with a severity and an escalate flag.

This is v1. The classifier does Bloom blocklist matching only.
It reports verdicts. It does not block traffic.
Port-scan and rate-anomaly detection are planned, not built.

## Hardware
- Raspberry Pi 5. Python, with scapy for capture and spidev for SPI.
- Basys 3 board, Xilinx Artix-7 (xc7a35t). Verilog, built with Vivado 2023.2.
- Link: SPI mode 0, 1 MHz, 20-byte frames. Four signal wires plus ground. The Pi is master.

## FPGA modules (`fpga/src/`)
- `spi_slave_rx.v`: SPI slave. Samples MOSI and assembles each 20-byte frame.
- `header_parser.v`: splits the 20-byte frame into header fields.
- `bloom_filter.v`: Bloom membership test. Two multiply-shift hashes over dual-port BRAM.
- `bloom_init.mem`: the Bloom bit-array, generated from the blocklist.
- `classifiers.v`: the classification stage. Currently the Bloom IP check.
- `verdict_encoder.v`: packs the result into the 20-byte verdict frame.
- `nids_top.v`: top level. Wires receiver, parser, classifier, and encoder to MISO.

## Pi modules
- `packet_capture.py`: sniff packets, extract the header, send over SPI, print the verdict.
- `spi_link.py`: SPI master wrapper over spidev.
- `verdict.py`: encode and decode verdict frames.
- `bloom.py`: build the Bloom bit-array from a blocklist. Writes `bloom_init.mem`.
- `classifier.py`: a CPU copy of the same classifier. Used as a reference and in the benchmark.
- `benchmark.py`: compares per-packet latency of the FPGA core against the Pi CPU.
- `spi_verdict_check.py`, `silicon_check.py`: clock known headers over the link and check the verdicts.
- `spi_loopback_test.py`, `spi_fpga_bringup.py`: SPI bring-up self-tests.
