/*  This file is part of ouster-parser.
 *
 *  assfonts is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation,
 *  either version 3 of the License,
 *  or (at your option) any later version.
 *
 *  assfonts is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty
 *  of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public
 *  License along with assfonts. If not, see <https://www.gnu.org/licenses/>.
 *
 *  written by wyzdwdz (https://github.com/wyzdwdz)
 */

mod ouster;
mod sequence;

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use clap::Parser;
use memmap2::Mmap;
use ouster::Legacy;
use packet::{ether, ip, udp, Packet};
use pcap_parser::{pcapng::Block, Capture, PcapBlock};

use crate::sequence::IPV4Seq;

#[derive(Parser)]
#[command(name = "ouster_parser")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Destination port of udp packets
    #[arg(short, long, value_name = "NUM")]
    port: u16,

    /// Ouster Lidar metadata json file
    #[arg(short, long, value_name = "FILE")]
    meta: PathBuf,

    /// Input pcap/pcapng file
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Output directory
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,

    /// Digit number of output PCD filenames
    #[arg(short, long, value_name = "NUM", default_value_t = 4)]
    digit: usize,
}

fn main() {
    let cli = Cli::parse();

    let pcap_file = File::open(cli.input).unwrap();
    let json_file = File::open(cli.meta).unwrap();

    let output_path = Path::new(&cli.output);

    let mmap = unsafe { Mmap::map(&pcap_file).unwrap() };

    let mut seq = IPV4Seq::new();
    let mut parser = ouster::Legacy::new(json_file, output_path, cli.digit);

    process_pcap_data(&mmap[..], cli.port, &mut seq, &mut parser);
}

fn process_pcap_data(data: &[u8], port: u16, seq: &mut IPV4Seq, parser: &mut Legacy) {
    match pcap_parser::parse_pcap(data) {
        Ok((_, capture)) => {
            for block in capture.iter() {
                process_capture_block(seq, &block, port, parser);
            }
        }
        Err(_) => match pcap_parser::parse_pcapng(data) {
            Ok((_, capture)) => {
                for block in capture.iter() {
                    process_capture_block(seq, &block, port, parser);
                }
            }
            Err(_) => {
                eprintln!("Unrecognized file format. (Neither pcap nor pcapng)");
            }
        },
    }
}

fn process_block(seq: &mut IPV4Seq, data: &[u8], port: u16, parser: &mut Legacy) {
    if let Some(data) = parse_packet(seq, &data, port) {
        parser.put(&data);
    }
}

fn process_capture_block(seq: &mut IPV4Seq, block: &PcapBlock, port: u16, parser: &mut Legacy) {
    match block {
        PcapBlock::Legacy(b) => {
            process_block(seq, &b.data[..b.origlen as usize], port, parser);
        }
        PcapBlock::NG(Block::EnhancedPacket(b)) => {
            process_block(seq, &b.data[..b.origlen as usize], port, parser);
        }
        _ => (),
    }
}

fn parse_packet(seq: &mut IPV4Seq, data: &[u8], port: u16) -> Option<Vec<u8>> {
    let ether = match ether::Packet::new(data) {
        Ok(ether) => ether,
        _ => return None,
    };

    let v4 = match ip::v4::Packet::new(ether.payload()) {
        Ok(v4) => v4,
        _ => return None,
    };

    let data = match seq.put_and_get(v4) {
        Some(data) => data,
        None => return None,
    };

    let udp = match udp::Packet::new(data) {
        Ok(udp) => udp,
        _ => return None,
    };

    if udp.destination() == port {
        Some(udp.payload().to_vec())
    } else {
        None
    }
}
