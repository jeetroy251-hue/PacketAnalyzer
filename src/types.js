/**
 * DPI Engine - Type Definitions
 * Converted from C++ to JavaScript
 */

// ============================================================================
// Application Type Enum
// ============================================================================
const AppType = {
    UNKNOWN: 0,
    HTTP: 1,
    HTTPS: 2,
    DNS: 3,
    TLS: 4,
    QUIC: 5,
    GOOGLE: 6,
    FACEBOOK: 7,
    YOUTUBE: 8,
    TWITTER: 9,
    INSTAGRAM: 10,
    NETFLIX: 11,
    AMAZON: 12,
    MICROSOFT: 13,
    APPLE: 14,
    WHATSAPP: 15,
    TELEGRAM: 16,
    TIKTOK: 17,
    SPOTIFY: 18,
    ZOOM: 19,
    DISCORD: 20,
    GITHUB: 21,
    CLOUDFLARE: 22,
    APP_COUNT: 23
};

// ============================================================================
// Connection State Enum
// ============================================================================
const ConnectionState = {
    NEW: 'NEW',
    ESTABLISHED: 'ESTABLISHED',
    CLASSIFIED: 'CLASSIFIED',
    BLOCKED: 'BLOCKED',
    CLOSED: 'CLOSED'
};

// ============================================================================
// Packet Action Enum
// ============================================================================
const PacketAction = {
    FORWARD: 'FORWARD',
    DROP: 'DROP',
    INSPECT: 'INSPECT',
    LOG_ONLY: 'LOG_ONLY'
};

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================
class FiveTuple {
    constructor(srcIp = 0, dstIp = 0, srcPort = 0, dstPort = 0, protocol = 0) {
        this.src_ip = srcIp;
        this.dst_ip = dstIp;
        this.src_port = srcPort;
        this.dst_port = dstPort;
        this.protocol = protocol;  // TCP=6, UDP=17
    }

    equals(other) {
        return this.src_ip === other.src_ip &&
               this.dst_ip === other.dst_ip &&
               this.src_port === other.src_port &&
               this.dst_port === other.dst_port &&
               this.protocol === other.protocol;
    }

    reverse() {
        return new FiveTuple(this.dst_ip, this.src_ip, this.dst_port, this.src_port, this.protocol);
    }

    toString() {
        const srcIpStr = ipToString(this.src_ip);
        const dstIpStr = ipToString(this.dst_ip);
        const protocolName = this.protocol === 6 ? 'TCP' : this.protocol === 17 ? 'UDP' : 'OTHER';
        return `${srcIpStr}:${this.src_port} -> ${dstIpStr}:${this.dst_port} (${protocolName})`;
    }

    getHash() {
        // Simple hash combining all fields
        let h = 0;
        h = hashCombine(h, this.src_ip);
        h = hashCombine(h, this.dst_ip);
        h = hashCombine(h, this.src_port);
        h = hashCombine(h, this.dst_port);
        h = hashCombine(h, this.protocol);
        return h;
    }

    getKey() {
        return `${this.src_ip}:${this.dst_ip}:${this.src_port}:${this.dst_port}:${this.protocol}`;
    }
}

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================
class Connection {
    constructor() {
        this.tuple = null;
        this.state = ConnectionState.NEW;
        this.app_type = AppType.UNKNOWN;
        this.sni = '';
        
        this.packets_in = 0;
        this.packets_out = 0;
        this.bytes_in = 0;
        this.bytes_out = 0;
        
        this.first_seen = Date.now();
        this.last_seen = Date.now();
        
        this.action = PacketAction.FORWARD;
        
        this.syn_seen = false;
        this.syn_ack_seen = false;
        this.fin_seen = false;
    }
}

// ============================================================================
// Packet Job - Contains all packet data
// ============================================================================
class PacketJob {
    constructor() {
        this.packet_id = 0;
        this.tuple = null;
        this.data = Buffer.alloc(0);  // Node.js Buffer
        this.eth_offset = 0;
        this.ip_offset = 0;
        this.transport_offset = 0;
        this.payload_offset = 0;
        this.payload_length = 0;
        this.tcp_flags = 0;
        this.payload_data = null;
        
        this.ts_sec = 0;
        this.ts_usec = 0;
    }
}

// ============================================================================
// PCAP Headers
// ============================================================================
class PcapGlobalHeader {
    constructor() {
        this.magic_number = 0xa1b2c3d4;
        this.version_major = 2;
        this.version_minor = 4;
        this.thiszone = 0;
        this.sigfigs = 0;
        this.snaplen = 65535;
        this.network = 1;  // Ethernet
    }

    toBuffer() {
        const buffer = Buffer.alloc(24);
        buffer.writeUInt32LE(this.magic_number, 0);
        buffer.writeUInt16LE(this.version_major, 4);
        buffer.writeUInt16LE(this.version_minor, 6);
        buffer.writeInt32LE(this.thiszone, 8);
        buffer.writeUInt32LE(this.sigfigs, 12);
        buffer.writeUInt32LE(this.snaplen, 16);
        buffer.writeUInt32LE(this.network, 20);
        return buffer;
    }

    static fromBuffer(buffer) {
        const header = new PcapGlobalHeader();
        header.magic_number = buffer.readUInt32LE(0);
        header.version_major = buffer.readUInt16LE(4);
        header.version_minor = buffer.readUInt16LE(6);
        header.thiszone = buffer.readInt32LE(8);
        header.sigfigs = buffer.readUInt32LE(12);
        header.snaplen = buffer.readUInt32LE(16);
        header.network = buffer.readUInt32LE(20);
        return header;
    }
}

class PcapPacketHeader {
    constructor() {
        this.ts_sec = 0;
        this.ts_usec = 0;
        this.incl_len = 0;
        this.orig_len = 0;
    }

    toBuffer() {
        const buffer = Buffer.alloc(16);
        buffer.writeUInt32LE(this.ts_sec, 0);
        buffer.writeUInt32LE(this.ts_usec, 4);
        buffer.writeUInt32LE(this.incl_len, 8);
        buffer.writeUInt32LE(this.orig_len, 12);
        return buffer;
    }

    static fromBuffer(buffer) {
        const header = new PcapPacketHeader();
        header.ts_sec = buffer.readUInt32LE(0);
        header.ts_usec = buffer.readUInt32LE(4);
        header.incl_len = buffer.readUInt32LE(8);
        header.orig_len = buffer.readUInt32LE(12);
        return header;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

function appTypeToString(appType) {
    const names = {
        [AppType.UNKNOWN]: 'UNKNOWN',
        [AppType.HTTP]: 'HTTP',
        [AppType.HTTPS]: 'HTTPS',
        [AppType.DNS]: 'DNS',
        [AppType.TLS]: 'TLS',
        [AppType.QUIC]: 'QUIC',
        [AppType.GOOGLE]: 'GOOGLE',
        [AppType.FACEBOOK]: 'FACEBOOK',
        [AppType.YOUTUBE]: 'YOUTUBE',
        [AppType.TWITTER]: 'TWITTER',
        [AppType.INSTAGRAM]: 'INSTAGRAM',
        [AppType.NETFLIX]: 'NETFLIX',
        [AppType.AMAZON]: 'AMAZON',
        [AppType.MICROSOFT]: 'MICROSOFT',
        [AppType.APPLE]: 'APPLE',
        [AppType.WHATSAPP]: 'WHATSAPP',
        [AppType.TELEGRAM]: 'TELEGRAM',
        [AppType.TIKTOK]: 'TIKTOK',
        [AppType.SPOTIFY]: 'SPOTIFY',
        [AppType.ZOOM]: 'ZOOM',
        [AppType.DISCORD]: 'DISCORD',
        [AppType.GITHUB]: 'GITHUB',
        [AppType.CLOUDFLARE]: 'CLOUDFLARE'
    };
    return names[appType] || 'UNKNOWN';
}

function sniToAppType(sni) {
    const lowerSni = sni.toLowerCase();
    
    if (lowerSni.includes('google.com') || lowerSni.includes('google')) return AppType.GOOGLE;
    if (lowerSni.includes('facebook.com') || lowerSni.includes('fb.com')) return AppType.FACEBOOK;
    if (lowerSni.includes('youtube.com') || lowerSni.includes('ytimg')) return AppType.YOUTUBE;
    if (lowerSni.includes('twitter.com') || lowerSni.includes('twitter')) return AppType.TWITTER;
    if (lowerSni.includes('instagram.com') || lowerSni.includes('instagram')) return AppType.INSTAGRAM;
    if (lowerSni.includes('netflix.com') || lowerSni.includes('netflix')) return AppType.NETFLIX;
    if (lowerSni.includes('amazon.com') || lowerSni.includes('amazon')) return AppType.AMAZON;
    if (lowerSni.includes('microsoft.com') || lowerSni.includes('azure')) return AppType.MICROSOFT;
    if (lowerSni.includes('apple.com') || lowerSni.includes('icloud')) return AppType.APPLE;
    if (lowerSni.includes('whatsapp.com') || lowerSni.includes('whatsapp')) return AppType.WHATSAPP;
    if (lowerSni.includes('telegram.org') || lowerSni.includes('telegram')) return AppType.TELEGRAM;
    if (lowerSni.includes('tiktok.com') || lowerSni.includes('tiktok')) return AppType.TIKTOK;
    if (lowerSni.includes('spotify.com') || lowerSni.includes('spotify')) return AppType.SPOTIFY;
    if (lowerSni.includes('zoom.us') || lowerSni.includes('zoom')) return AppType.ZOOM;
    if (lowerSni.includes('discord.com') || lowerSni.includes('discord')) return AppType.DISCORD;
    if (lowerSni.includes('github.com') || lowerSni.includes('github')) return AppType.GITHUB;
    if (lowerSni.includes('cloudflare.com') || lowerSni.includes('cloudflare')) return AppType.CLOUDFLARE;
    
    return AppType.UNKNOWN;
}

function stringToAppType(name) {
    if (!name) return AppType.UNKNOWN;
    const text = name.toString().trim().toUpperCase();
    switch (text) {
        case 'UNKNOWN': return AppType.UNKNOWN;
        case 'HTTP': return AppType.HTTP;
        case 'HTTPS': return AppType.HTTPS;
        case 'DNS': return AppType.DNS;
        case 'TLS': return AppType.TLS;
        case 'QUIC': return AppType.QUIC;
        case 'GOOGLE': return AppType.GOOGLE;
        case 'FACEBOOK': return AppType.FACEBOOK;
        case 'YOUTUBE': return AppType.YOUTUBE;
        case 'TWITTER': return AppType.TWITTER;
        case 'INSTAGRAM': return AppType.INSTAGRAM;
        case 'NETFLIX': return AppType.NETFLIX;
        case 'AMAZON': return AppType.AMAZON;
        case 'MICROSOFT': return AppType.MICROSOFT;
        case 'APPLE': return AppType.APPLE;
        case 'WHATSAPP': return AppType.WHATSAPP;
        case 'TELEGRAM': return AppType.TELEGRAM;
        case 'TIKTOK': return AppType.TIKTOK;
        case 'SPOTIFY': return AppType.SPOTIFY;
        case 'ZOOM': return AppType.ZOOM;
        case 'DISCORD': return AppType.DISCORD;
        case 'GITHUB': return AppType.GITHUB;
        case 'CLOUDFLARE': return AppType.CLOUDFLARE;
        default: return AppType.UNKNOWN;
    }
}

function ipToString(ipNum) {
    const b1 = (ipNum) & 0xFF;
    const b2 = (ipNum >> 8) & 0xFF;
    const b3 = (ipNum >> 16) & 0xFF;
    const b4 = (ipNum >> 24) & 0xFF;
    return `${b1}.${b2}.${b3}.${b4}`;
}

function stringToIp(ipStr) {
    const parts = ipStr.split('.');
    if (parts.length !== 4) return 0;
    let result = 0;
    for (let i = 0; i < 4; i++) {
        result |= (parseInt(parts[i]) & 0xFF) << (i * 8);
    }
    return result >>> 0;  // Ensure unsigned
}

function hashCombine(hash, value) {
    const prime = 0x9e3779b9;
    return (hash ^ (value + prime + (hash << 6) + (hash >> 2))) >>> 0;
}

module.exports = {
    AppType,
    ConnectionState,
    PacketAction,
    FiveTuple,
    Connection,
    PacketJob,
    PcapGlobalHeader,
    PcapPacketHeader,
    appTypeToString,
    sniToAppType,
    stringToAppType,
    ipToString,
    stringToIp,
    hashCombine
};
