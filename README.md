# ouster-parser

Parse pcap/pcapng file to extract Ouster Lidar data and write them into PCD files

!! Only support LEGACY Lidar data packet format !!

```
Parse pcap file to extract Ouster Lidar data and write them into PCD files

Usage: ouster_parser [OPTIONS] --port <NUM> --meta <FILE> --input <FILE> --output <DIR>

Options:
  -p, --port <NUM>    Destination port of udp packets
  -m, --meta <FILE>   Ouster Lidar metadata json file
  -i, --input <FILE>  Input pcap/pcapng file
  -o, --output <DIR>  Output directory
  -d, --digit <NUM>   Digit number of output PCD filenames [default: 4]
  -h, --help          Print help
  -V, --version       Print version
 ```
