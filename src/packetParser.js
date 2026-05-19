/**
 * Packet Parser - Parse raw packets and extract information
 * Converted from C++ to JavaScript
 */

const { RawPacket } = require('./pcapReader');

// TCP Flag constants
const TCPFlags = {
    FIN: 0x01,
    SYN: 0x02,
    RST: 0x04,
    PSH: 0x08,
    ACK: 0x10,
    URG: 0x20
};

// Protocol numbers
const Protocol = {
    ICMP: 1,
    TCP: 6,
    UDP: 17
};

// EtherType values
const EtherType = {
    IPv4: 0x0800,
    IPv6: 0x86DD,
    ARP: 0x0806
};

// Parsed packet information
class ParsedPacket {
    constructor() {
        this.timestamp_sec = 0;
        this.timestamp_usec = 0;
        
        this.src_mac = '';
        this.dest_mac = '';
        this.ether_type = 0;
        
        this.has_ip = false;
        this.ip_version = 0;
        this.src_ip = '';
        this.dest_ip = '';
        this.protocol = 0;
        this.ttl = 0;
        
        this.has_tcp = false;
        this.has_udp = false;
        this.src_port = 0;
        this.dest_port = 0;
        
        this.tcp_flags = 0;
        this.seq_number = 0;
        this.ack_number = 0;
        
        this.payload_length = 0;
        this.payload_data = null;
    }
}

class PacketParser {
    static parse(raw, parsed) {
        // Initialize parsed packet
        Object.assign(parsed, new ParsedPacket());
        parsed.timestamp_sec = raw.header.ts_sec;
        parsed.timestamp_usec = raw.header.ts_usec;
        
        const data = raw.data;
        let offset = 0;
        
        // Parse Ethernet header first
        if (!this.parseEthernet(data, parsed, offset)) {
            return false;
        }
        offset = 14;  // Ethernet header is always 14 bytes
        
        // Parse IP layer if it's IPv4
        if (parsed.ether_type === EtherType.IPv4) {
            if (!this.parseIPv4(data, parsed, offset)) {
                return false;
            }
            
            // Parse transport layer based on protocol
            if (parsed.protocol === Protocol.TCP) {
                if (!this.parseTCP(data, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol === Protocol.UDP) {
                if (!this.parseUDP(data, parsed, offset)) {
                    return false;
                }
            }
        }
        
        // Set payload information
        if (offset < data.length) {
            parsed.payload_length = data.length - offset;
            parsed.payload_data = data.slice(offset);
        } else {
            parsed.payload_length = 0;
            parsed.payload_data = null;
        }
        
        return true;
    }

    static parseEthernet(data, parsed, offset) {
        const ETH_HEADER_LEN = 14;
        
        if (data.length < ETH_HEADER_LEN) {
            return false;
        }
        
        // Parse destination MAC (bytes 0-5)
        parsed.dest_mac = this.macToString(data, 0);
        
        // Parse source MAC (bytes 6-11)
        parsed.src_mac = this.macToString(data, 6);
        
        // Parse EtherType (bytes 12-13, big-endian)
        parsed.ether_type = data.readUInt16BE(12);
        
        return true;
    }

    static parseIPv4(data, parsed, offset) {
        const MIN_IP_HEADER_LEN = 20;
        
        if (data.length < offset + MIN_IP_HEADER_LEN) {
            return false;
        }
        
        const ipData = data.slice(offset);
        
        // First byte: version (4 bits) + IHL (4 bits)
        const versionIhl = ipData[0];
        parsed.ip_version = (versionIhl >> 4) & 0x0F;
        const ihl = versionIhl & 0x0F;
        
        if (parsed.ip_version !== 4) {
            return false;
        }
        
        const ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || data.length < offset + ipHeaderLen) {
            return false;
        }
        
        // Parse fields
        parsed.ttl = ipData[8];
        parsed.protocol = ipData[9];
        
        // Source IP (bytes 12-15)
        const srcIp = ipData.readUInt32BE(12);
        parsed.src_ip = this.ipToString(srcIp);
        
        // Destination IP (bytes 16-19)
        const destIp = ipData.readUInt32BE(16);
        parsed.dest_ip = this.ipToString(destIp);
        
        parsed.has_ip = true;
        // Update offset in the caller's context
        // Note: We return ipHeaderLen so caller can update offset
        return ipHeaderLen;
    }

    static parseTCP(data, parsed, offset) {
        const MIN_TCP_HEADER_LEN = 20;
        
        if (data.length < offset + MIN_TCP_HEADER_LEN) {
            return false;
        }
        
        const tcpData = data.slice(offset);
        
        // Source port (bytes 0-1)
        parsed.src_port = tcpData.readUInt16BE(0);
        
        // Destination port (bytes 2-3)
        parsed.dest_port = tcpData.readUInt16BE(2);
        
        // Sequence number (bytes 4-7)
        parsed.seq_number = tcpData.readUInt32BE(4);
        
        // Acknowledgment number (bytes 8-11)
        parsed.ack_number = tcpData.readUInt32BE(8);
        
        // Data offset (upper 4 bits of byte 12)
        const dataOffset = (tcpData[12] >> 4) & 0x0F;
        const tcpHeaderLen = dataOffset * 4;
        
        // Flags (byte 13)
        parsed.tcp_flags = tcpData[13];
        
        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || data.length < offset + tcpHeaderLen) {
            return false;
        }
        
        parsed.has_tcp = true;
        return true;
    }

    static parseUDP(data, parsed, offset) {
        const UDP_HEADER_LEN = 8;
        
        if (data.length < offset + UDP_HEADER_LEN) {
            return false;
        }
        
        const udpData = data.slice(offset);
        
        // Source port (bytes 0-1)
        parsed.src_port = udpData.readUInt16BE(0);
        
        // Destination port (bytes 2-3)
        parsed.dest_port = udpData.readUInt16BE(2);
        
        parsed.has_udp = true;
        return true;
    }

    static macToString(data, offset) {
        let result = '';
        for (let i = 0; i < 6; i++) {
            if (i > 0) result += ':';
            result += data[offset + i].toString(16).padStart(2, '0');
        }
        return result;
    }

    static ipToString(ip) {
        return `${(ip >> 0) & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
    }

    static protocolToString(protocol) {
        switch (protocol) {
            case Protocol.ICMP: return 'ICMP';
            case Protocol.TCP: return 'TCP';
            case Protocol.UDP: return 'UDP';
            default: return `Unknown(${protocol})`;
        }
    }

    static tcpFlagsToString(flags) {
        let result = '';
        if (flags & TCPFlags.SYN) result += 'SYN ';
        if (flags & TCPFlags.ACK) result += 'ACK ';
        if (flags & TCPFlags.FIN) result += 'FIN ';
        if (flags & TCPFlags.RST) result += 'RST ';
        if (flags & TCPFlags.PSH) result += 'PSH ';
        if (flags & TCPFlags.URG) result += 'URG ';
        return result.trim() || 'none';
    }
}

module.exports = {
    PacketParser,
    ParsedPacket,
    TCPFlags,
    Protocol,
    EtherType
};
