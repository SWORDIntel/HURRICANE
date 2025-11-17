//! Raw packet processing for high-speed scanning
//!
//! Provides low-level TCP/IP packet construction and parsing
//! for SYN scanning and custom packet manipulation.

use std::net::Ipv4Addr;
use bytes::BytesMut;

/// TCP packet structure for SYN scanning
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpPacket {
    // IP Header (20 bytes)
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: u32,
    pub dest_ip: u32,

    // TCP Header (20 bytes minimum)
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub data_offset_flags: u16,
    pub window_size: u16,
    pub tcp_checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpPacket {
    /// Create SYN packet for port scanning
    pub fn new_syn(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Self {
        let mut packet = TcpPacket {
            // IP Header
            version_ihl: 0x45, // IPv4, 20-byte header
            tos: 0,
            total_length: 40u16.to_be(), // IP + TCP headers
            identification: rand::random::<u16>().to_be(),
            flags_offset: 0x4000u16.to_be(), // Don't fragment
            ttl: 64,
            protocol: 6, // TCP
            checksum: 0,
            source_ip: u32::from(source_ip).to_be(),
            dest_ip: u32::from(dest_ip).to_be(),

            // TCP Header
            source_port: source_port.to_be(),
            dest_port: dest_port.to_be(),
            sequence: rand::random::<u32>().to_be(),
            acknowledgment: 0,
            data_offset_flags: 0x5002u16.to_be(), // 20-byte header, SYN flag
            window_size: 65535u16.to_be(),
            tcp_checksum: 0,
            urgent_pointer: 0,
        };

        // Calculate checksums
        packet.checksum = packet.calculate_ip_checksum();
        packet.tcp_checksum = packet.calculate_tcp_checksum();

        packet
    }

    /// Calculate IP header checksum
    pub fn calculate_ip_checksum(&self) -> u16 {
        let mut sum = 0u32;

        // Sum all 16-bit words in IP header (excluding checksum field)
        let words = unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u16,
                10, // 20 bytes = 10 words
            )
        };

        for (i, &word) in words.iter().enumerate() {
            if i != 5 { // Skip checksum field
                sum += u16::from_be(word) as u32;
            }
        }

        // Add carry
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        (!sum as u16).to_be()
    }

    /// Calculate TCP checksum with pseudo-header
    pub fn calculate_tcp_checksum(&self) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header
        sum += (self.source_ip >> 16) as u32;
        sum += (self.source_ip & 0xFFFF) as u32;
        sum += (self.dest_ip >> 16) as u32;
        sum += (self.dest_ip & 0xFFFF) as u32;
        sum += self.protocol as u32;
        sum += 20; // TCP header length

        // TCP header
        let tcp_start = 20; // Offset to TCP header
        let words = unsafe {
            std::slice::from_raw_parts(
                (self as *const _ as *const u8).add(tcp_start) as *const u16,
                10, // 20 bytes = 10 words
            )
        };

        for (i, &word) in words.iter().enumerate() {
            if i != 8 { // Skip checksum field
                sum += u16::from_be(word) as u32;
            }
        }

        // Add carry
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        (!sum as u16).to_be()
    }

    /// Convert to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = self as *const _ as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<TcpPacket>()).to_vec()
        }
    }

    /// Parse from received bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<TcpPacket>() {
            return None;
        }

        unsafe {
            let packet = (bytes.as_ptr() as *const TcpPacket).read_unaligned();
            Some(packet)
        }
    }

    /// Check if packet is SYN-ACK response
    pub fn is_syn_ack(&self) -> bool {
        let flags = u16::from_be(self.data_offset_flags) & 0x3F;
        flags == 0x12 // SYN + ACK
    }

    /// Get destination port (converted from network byte order)
    pub fn get_dest_port(&self) -> u16 {
        u16::from_be(self.dest_port)
    }
}

/// Batch packet builder for high-throughput scanning
pub struct PacketBatch {
    packets: Vec<TcpPacket>,
    buffer: BytesMut,
}

impl PacketBatch {
    pub fn new(capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            buffer: BytesMut::with_capacity(capacity * 40),
        }
    }

    /// Add SYN packet to batch
    pub fn add_syn(&mut self, source_ip: Ipv4Addr, dest_ip: Ipv4Addr, source_port: u16, dest_port: u16) {
        let packet = TcpPacket::new_syn(source_ip, dest_ip, source_port, dest_port);
        self.packets.push(packet);
    }

    /// Serialize all packets to buffer
    pub fn serialize(&mut self) -> &[u8] {
        self.buffer.clear();

        for packet in &self.packets {
            self.buffer.extend_from_slice(&packet.to_bytes());
        }

        &self.buffer
    }

    /// Clear batch for reuse
    pub fn clear(&mut self) {
        self.packets.clear();
        self.buffer.clear();
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syn_packet_creation() {
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let dest = Ipv4Addr::new(192, 168, 1, 1);
        let packet = TcpPacket::new_syn(source, dest, 12345, 80);

        assert_eq!(packet.protocol, 6); // TCP
        assert_eq!(u16::from_be(packet.dest_port), 80);
    }

    #[test]
    fn test_packet_batch() {
        let mut batch = PacketBatch::new(100);
        let source = Ipv4Addr::new(192, 168, 1, 100);
        let dest = Ipv4Addr::new(192, 168, 1, 1);

        for port in 1..=100 {
            batch.add_syn(source, dest, 12345, port);
        }

        assert_eq!(batch.len(), 100);

        let bytes = batch.serialize();
        assert_eq!(bytes.len(), 100 * 40); // 40 bytes per packet
    }
}
