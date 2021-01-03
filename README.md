Yet another PCAP tool
=====================

Runs some useful statistics on PCAP files. Built to be used on large pcap files (10GB+) to quickly identify the main IP addresses and protocols within the traffic.
Currently implemented statistics (for each IP address seen):
- Bytes Sent
- Bytes Received
- Bytes Total
- Packets Sent
- Packets Received
- Packets Total
- Bytes Total / Port (only for destination IP) !TODO!

How to install
--------------

1. Clone the repo
2. Create a virtual environment in the folder: `python3 -m venv .venv`
3. Activate the venv: `source ./.venv/bin/activate`
4. Install dependencies: `python3 -m pip install -r requirements.txt`

How to run
----------

1. Activate the venv: `source ./.venv/bin/activate`
2. Run the script

Syntax
------
```
usage: pcap.py [-h] --input FILE [--mode {stats}] [--top TOP] [--column {pkt_sent,pkt_recv,pkt_total,bytes_sent,bytes_recv,bytes_total}]

optional arguments:
  -h, --help            show this help message and exit
  --input FILE          Specify the name of the pcap file to read.
  --mode {stats}        Select which operation to perform on the input file. Default is stats.
  --top TOP             How many entries to show for statistics. Used with for stats mode. Default is 10.
  --column {pkt_sent,pkt_recv,pkt_total,bytes_sent,bytes_recv,bytes_total}
                        Which column to sort on. Default is `bytes_total`. Sort is always descending.
```
