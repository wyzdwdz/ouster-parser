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

use core::f32::consts::PI;
use std::{
    fs::File,
    io::prelude::*,
    path::{Path, PathBuf},
    sync::mpsc::{self, Sender},
};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Deserialize;
use serde_json;

#[derive(Deserialize)]
struct MetaData {
    beam_altitude_angles: Vec<f32>,
    beam_azimuth_angles: Vec<f32>,
    beam_to_lidar_transform: Vec<f32>,
    data_format: DataFormat,
}

#[derive(Deserialize)]
struct DataFormat {
    columns_per_frame: usize,
    columns_per_packet: usize,
    pixels_per_column: usize,
}

struct HeaderBlock {
    timestamp: u64,
    measure_id: u16,
    frame_id: u16,
}

struct PointXYZ {
    x: f32,
    y: f32,
    z: f32,
    reflect: f32,
}

struct FileData {
    header: String,
    data: Vec<u8>,
    path: PathBuf,
}

pub struct Legacy<'a> {
    metadata: MetaData,

    n: f32,
    azimuths: Vec<f32>,
    cos_phis: Vec<f32>,
    sin_phis: Vec<f32>,

    current_frame: u16,
    current_timestamp: u64,
    current_points: Vec<f32>,
    current_num_points: usize,
    current_broken: bool,

    output_path: &'a Path,
    id: usize,
    digit: usize,

    sender: Sender<FileData>,
}

impl<'a> Legacy<'a> {
    pub fn new(meta_file: File, output_path: &'a Path, digit: usize) -> Self {
        let metadata: MetaData = serde_json::from_reader(meta_file).unwrap();

        let beam_to_lidar = &metadata.beam_to_lidar_transform;
        let beam_azimuth_angles = &metadata.beam_azimuth_angles;
        let beam_altitude_angles = &metadata.beam_altitude_angles;

        let n = (beam_to_lidar[3].powi(2) + beam_to_lidar[11].powi(2)).sqrt();
        let azimuths: Vec<f32> = beam_azimuth_angles
            .iter()
            .map(|x| -2.0 * PI * (x / 360.0))
            .collect();
        let cos_phis: Vec<f32> = beam_altitude_angles
            .iter()
            .map(|x| (2.0 * PI * (x / 360.0)).cos())
            .collect();
        let sin_phis: Vec<f32> = beam_altitude_angles
            .iter()
            .map(|x| (2.0 * PI * (x / 360.0)).sin())
            .collect();

        let (sender, receiver) = mpsc::channel::<FileData>();

        std::thread::spawn(move || {
            for file_data in receiver {
                let mut file = File::create(file_data.path).unwrap();
                file.write_all(file_data.header.as_bytes()).unwrap();
                file.write_all(file_data.data.as_slice()).unwrap();
            }
        });

        Self {
            metadata,
            n,
            azimuths,
            cos_phis,
            sin_phis,
            current_frame: 0,
            current_timestamp: 0,
            current_points: Vec::new(),
            current_num_points: 0,
            current_broken: false,
            output_path,
            id: 0,
            digit,
            sender,
        }
    }

    pub fn put(&mut self, data: &[u8]) {
        let pixels_per_column = self.metadata.data_format.pixels_per_column;
        let columns_per_packet = self.metadata.data_format.columns_per_packet;

        let len_column = 20 + pixels_per_column * 12;
        let len_expected = columns_per_packet * len_column;

        if data.len() < len_expected {
            self.current_broken = true;
            return;
        }

        for offset in (0..data.len()).step_by(len_column) {
            self.parse_measure_block(&data[offset..offset + len_column]);
        }
    }

    fn parse_measure_block(&mut self, data: &[u8]) {
        let mut block_status_slice = &data[data.len() - 4..];
        let block_status = block_status_slice.read_u32::<LittleEndian>().unwrap();

        if block_status != 0xffffffff {
            self.current_broken = true;
            return;
        }

        let mut header = HeaderBlock {
            timestamp: 0,
            measure_id: 0,
            frame_id: 0,
        };

        let mut timestamp_slice = &data[..8];
        header.timestamp = timestamp_slice.read_u64::<LittleEndian>().unwrap();

        let mut measure_id_slice = &data[8..10];
        header.measure_id = measure_id_slice.read_u16::<LittleEndian>().unwrap();

        let mut frame_id_slice = &data[10..12];
        header.frame_id = frame_id_slice.read_u16::<LittleEndian>().unwrap();

        if !self.set_current_state(&header) {
            return;
        }

        let mut channel = 0;

        for offset in (16..data.len() - 4).step_by(12) {
            self.parse_data_block(&data[offset..offset + 12], header.measure_id, channel);
            channel += 1;
            self.current_num_points += 1;
        }
    }

    fn parse_data_block(&mut self, data: &[u8], measure_id: u16, channel: usize) {
        let mut range_slice = &data[..4];
        let range = range_slice.read_u32::<LittleEndian>().unwrap() << 12 >> 12;

        let reflect = data[4];

        if range == 0 || reflect == 0 {
            return;
        }

        let point = self.calculate_xyz(range as f32, reflect as f32, measure_id as f32, channel);

        self.current_points.push(point.x);
        self.current_points.push(point.y);
        self.current_points.push(point.z);
        self.current_points.push(point.reflect);
    }

    fn set_current_state(&mut self, header: &HeaderBlock) -> bool {
        let columns_per_frame = self.metadata.data_format.columns_per_frame;
        let pixels_per_column = self.metadata.data_format.pixels_per_column;

        if self.current_broken {
            if header.frame_id != self.current_frame {
                self.current_broken = false;
                self.current_points.clear();
                self.current_num_points = 0;
                return self.set_current_state(&header);
            } else {
                return false;
            }
        } else {
            if header.frame_id != self.current_frame {
                if self.current_num_points >= columns_per_frame * pixels_per_column {
                    self.save_pcd();
                }

                self.current_points.clear();
                self.current_num_points = 0;
                self.current_frame = header.frame_id;
                self.current_timestamp = header.timestamp;
            } else {
                if header.timestamp < self.current_timestamp {
                    self.current_timestamp = header.timestamp;
                }
            }

            true
        }
    }

    fn calculate_xyz(&self, range: f32, reflect: f32, measure_id: f32, channel: usize) -> PointXYZ {
        let mut point = PointXYZ {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            reflect: 0.0,
        };

        let column_per_frame = self.metadata.data_format.columns_per_frame as f32;
        let beam_to_lidar = &self.metadata.beam_to_lidar_transform;

        let encoder = 2.0 * PI * (1.0 - measure_id / column_per_frame);

        point.x =
            ((range - self.n) * (encoder + self.azimuths[channel]).cos() * self.cos_phis[channel]
                + beam_to_lidar[3] * encoder.cos())
                / 1000.0;

        point.y =
            ((range - self.n) * (encoder + self.azimuths[channel]).sin() * self.cos_phis[channel]
                + beam_to_lidar[3] * encoder.sin())
                / 1000.0;

        point.z = ((range - self.n) * self.sin_phis[channel] + beam_to_lidar[11]) / 1000.0;

        point.reflect = reflect / u8::MAX as f32;

        point
    }

    fn save_pcd(&mut self) {
        //// safe but slow
        // let buffer: Vec<u8> = self
        //     .current_points
        //     .iter()
        //     .flat_map(|x| x.to_le_bytes().to_vec())
        //     .collect();

        // unsafe little endian in x86
        let buffer = unsafe {
            std::slice::from_raw_parts(
                self.current_points.as_ptr() as *const u8,
                self.current_points.len() * std::mem::size_of::<f32>(),
            )
        };

        let pcd_header = format!(
            "# .PCD v.7 - Point Cloud Data file format\n\
             # timestamp: {}\n\
             VERSION .7\n\
             FIELDS x y z intensity\n\
             SIZE 4 4 4 4\n\
             TYPE F F F F\n\
             COUNT 1 1 1 1\n\
             WIDTH {}\n\
             HEIGHT 1\n\
             VIEWPOINT 0 0 0 1 0 0 0\n\
             POINTS {}\n\
             DATA binary\n",
            self.current_timestamp,
            self.current_points.len() / 4,
            self.current_points.len() / 4
        );

        let width = self.digit;

        let filename = format!("{:0width$}.pcd", self.id);
        let file_path = self.output_path.join(filename);

        let file_data = FileData {
            header: pcd_header,
            data: buffer.to_vec(),
            path: file_path,
        };

        self.sender.send(file_data).unwrap();

        self.id += 1;
    }
}
