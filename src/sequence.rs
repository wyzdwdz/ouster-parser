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

use core::net::Ipv4Addr;
use std::{collections::HashMap, usize, vec::Vec};

use packet::{ip, Packet};

const PACKET_MAX_SIZE: usize = 0xFFFF;

#[derive(Eq, Hash, PartialEq, Clone, Copy)]
struct IPV4Key {
    source: Ipv4Addr,
    dest: Ipv4Addr,
    proto: u8,
    id: u16,
}

struct IPV4Hole {
    first: u16,
    last: u16,
}

struct IPV4Chunk {
    data: [u8; PACKET_MAX_SIZE],
    holes: Vec<IPV4Hole>,
    len: u16,
}

impl IPV4Chunk {
    fn new() -> Self {
        let data = [0; PACKET_MAX_SIZE];
        let mut holes = Vec::new();
        let hole = IPV4Hole {
            first: 0,
            last: PACKET_MAX_SIZE as u16,
        };
        holes.push(hole);

        Self {
            data,
            holes,
            len: PACKET_MAX_SIZE as u16,
        }
    }
}

pub struct IPV4Seq {
    buffer: HashMap<IPV4Key, IPV4Chunk>,
}

impl IPV4Seq {
    pub fn new() -> Self {
        let buffer = HashMap::new();

        Self { buffer }
    }

    pub fn put_and_get(&mut self, pkt: ip::v4::Packet<&[u8]>) -> Option<Vec<u8>> {
        let offset = pkt.offset();
        let length = pkt.payload().len() as u16;
        let flags = pkt.flags();
        let mf = flags.contains(ip::v4::Flags::MORE_FRAGMENTS);
        let df = flags.contains(ip::v4::Flags::DONT_FRAGMENT);
        let payload = pkt.payload();

        if df {
            return Some(pkt.payload().to_vec());
        }

        if mf && (length % 8) != 0 {
            return None;
        }

        let data_first = offset * 8;
        let data_last = data_first + length;

        if data_last < data_first {
            return None;
        }

        let key = IPV4Key {
            source: pkt.source(),
            dest: pkt.destination(),
            proto: pkt.protocol().into(),
            id: pkt.id(),
        };

        if !self.buffer.contains_key(&key) {
            self.buffer.insert(key, IPV4Chunk::new());
        }

        {
            let chunk = self.buffer.get_mut(&key).unwrap();

            let mut append_list = Vec::new();
            let mut remove_index = usize::MAX;

            if !mf {
                chunk.len = data_last;
            }

            for (index, hole) in chunk.holes.iter().enumerate() {
                if data_first < hole.last && data_last > hole.first {
                    if data_first < hole.first || data_last > hole.last {
                        self.buffer.clear();
                        return None;
                    }

                    if data_first > hole.first {
                        let new_hole = IPV4Hole {
                            first: hole.first,
                            last: data_first,
                        };

                        append_list.push(new_hole);
                    }

                    if data_last < hole.last && mf {
                        let new_hole = IPV4Hole {
                            first: data_last,
                            last: hole.last,
                        };

                        append_list.push(new_hole);
                    }

                    remove_index = index;
                    break;
                }
            }

            if remove_index != usize::MAX {
                chunk.holes.remove(remove_index);
            }

            if !append_list.is_empty() {
                chunk.holes.append(&mut append_list);
            }

            chunk.data[data_first as usize..][..payload.len()].copy_from_slice(payload);
        }

        let mut remove_key: IPV4Key = IPV4Key {
            source: Ipv4Addr::new(0, 0, 0, 0),
            dest: Ipv4Addr::new(0, 0, 0, 0),
            proto: 0,
            id: 0,
        };

        let mut vec_data = Vec::new();

        for (key, buffer) in &self.buffer {
            if buffer.holes.is_empty() {
                remove_key = key.clone();
                vec_data = buffer.data[..buffer.len as usize].to_vec();
                break;
            }
        }

        if vec_data.is_empty() {
            None
        } else {
            self.buffer.remove(&remove_key);
            Some(vec_data)
        }
    }
}
