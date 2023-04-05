extern crate pcap;

use pcap::{Capture, Device};
use std::env;
use std::process;

fn main() {
    // Get the network interface as a command-line argument
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <INTERFACE>", args[0]);
        process::exit(1);
    }

    let interface = &args[1];

    let device = Device::list()
        .unwrap_or_else(|err| {
            eprintln!("Error listing devices: {}", err);
            process::exit(1);
        })
        .into_iter()
        .find(|device| device.name == *interface)
        .unwrap_or_else(|| {
            eprintln!("Error: Device {} not found", interface);
            process::exit(1);
        });

    // Create a capture object for the specified interface
    let mut capture = Capture::from_device(device)
        .unwrap_or_else(|err| {
            eprintln!("Error creating capture for device {}: {}", interface, err);
            process::exit(1);
        })
        .promisc(true)
        .snaplen(2048)
        .open()
        .unwrap_or_else(|err| {
            eprintln!("Error opening capture: {}", err);
            process::exit(1);
        });

    // Process packets
    loop {
        match capture.next() {
            Ok(packet) => {
                print_packet_data(packet.data);
                println!("####################################################################")
            }
            Err(err) => {
                eprintln!("Error capturing packet: {}", err);
                break;
            }
        }
    }
}

fn print_packet_data(data: &[u8]) {
    const HEX_CHARS_PER_LINE: usize = 16;

    for (i, byte) in data.iter().enumerate() {
        if i % HEX_CHARS_PER_LINE == 0 {
            print!("{:04x}: ", i);
        }

        print!("{:02x} ", byte);

        if i % HEX_CHARS_PER_LINE == HEX_CHARS_PER_LINE - 1 || i == data.len() - 1 {
            let padding = 3 * (HEX_CHARS_PER_LINE - (i % HEX_CHARS_PER_LINE) - 1);
            print!("{:padding$}", "", padding = padding);

            let start = i / HEX_CHARS_PER_LINE * HEX_CHARS_PER_LINE;
            let end = std::cmp::min(start + HEX_CHARS_PER_LINE, data.len());

            for byte in &data[start..end] {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    print!("{}", *byte as char);
                } else {
                    print!(".");
                }
            }

            println!();
        }
    }
}
