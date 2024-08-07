# ouster-parser

Parse pcap/pcapng file to extract Ouster Lidar data and write them into PCD files

!! Only support LEGACY Lidar data packet format !!

```
Parse pcap file to extract Ouster Lidar data

Usage: ouster_parser.exe --port <NUM> --meta <FILE> --input <FILE> --output <DIR>

Options:
  -p, --port <NUM>    Destination port of udp packets
  -m, --meta <FILE>   Ouster Lidar metadata json file
  -i, --input <FILE>  Input pcap/pcapng file
  -o, --output <DIR>  Output directory
  -h, --help          Print help
  -V, --version       Print version
 ```