# Port Scanner

This is a simple Python port scanner that allows you to check open ports on a given IP address. The script uses threading for concurrent scanning of ports and provides various command-line arguments for customization.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Command-line Arguments](#command-line-arguments)

## Features

- Scans open ports on a specified IP address.
- Supports scanning a range of ports or user-defined ports.
- Utilizes threading for concurrent port scanning.
- Provides verbose output for detailed information.
- Validates IP addresses and handles common errors.

## Getting Started

### Prerequisites

- Python 3.x

### Installation

- git clone https://github.com/W1ck29/Port-Scanner.git
- cd port-scanner
- pip install -r requirements.txt


### Usage
    python portscanner.py -ip 192.168.0.1 -min 1 -max 1000
    python portscanner.py -ip 192.168.0.1 -ip 192.168.0.2 -p 80 -p 443

## Command-line Arguments
- -ip: IP address(es) to be scanned.
- -min: Start port for scanning (default: 1).
- -max: End port for scanning (default: 10,000).
- -v or --verbose: Increase verbosity for detailed output.
- -p or --port: Specify individual ports for scanning.