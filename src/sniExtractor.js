/**
 * SNI and Payload Extractors - Extract domain information from packets
 * Converted from C++ to JavaScript
 */

// TLS SNI Constants
const CONTENT_TYPE_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const EXTENSION_SNI = 0x0000;
const SNI_TYPE_HOSTNAME = 0x00;

class SNIExtractor {
    static readUint16BE(data, offset) {
        return (data[offset] << 8) | data[offset + 1];
    }

    static readUint24BE(data, offset) {
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    }

    static isTLSClientHello(payload, length) {
        // Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if (length < 9) return false;
        
        // Check TLS record header
        // Byte 0: Content Type (should be 0x16 = Handshake)
        if (payload[0] !== CONTENT_TYPE_HANDSHAKE) return false;
        
        // Bytes 1-2: TLS Version
        const version = this.readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;
        
        // Bytes 3-4: Record length
        const recordLength = this.readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;
        
        // Check handshake header (starts at byte 5)
        // Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if (payload[5] !== HANDSHAKE_CLIENT_HELLO) return false;
        
        return true;
    }

    static extract(payload, length) {
        if (!this.isTLSClientHello(payload, length)) {
            return null;
        }
        
        // Skip TLS record header (5 bytes)
        let offset = 5;
        
        // Skip handshake header
        const handshakeLength = this.readUint24BE(payload, offset + 1);
        offset += 4;
        
        // Client Hello body
        // Client version (2 bytes)
        offset += 2;
        
        // Random (32 bytes)
        offset += 32;
        
        // Session ID
        if (offset >= length) return null;
        const sessionIdLength = payload[offset];
        offset += 1 + sessionIdLength;
        
        // Cipher suites
        if (offset + 2 > length) return null;
        const cipherSuitesLength = this.readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;
        
        // Compression methods
        if (offset >= length) return null;
        const compressionMethodsLength = payload[offset];
        offset += 1 + compressionMethodsLength;
        
        // Extensions
        if (offset + 2 > length) return null;
        const extensionsLength = this.readUint16BE(payload, offset);
        offset += 2;
        
        let extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length;
        }
        
        // Parse extensions to find SNI
        while (offset + 4 <= extensionsEnd) {
            const extensionType = this.readUint16BE(payload, offset);
            const extensionLength = this.readUint16BE(payload, offset + 2);
            offset += 4;
            
            if (offset + extensionLength > extensionsEnd) break;
            
            if (extensionType === EXTENSION_SNI) {
                // SNI extension found
                if (extensionLength < 5) break;
                
                const sniListLength = this.readUint16BE(payload, offset);
                if (sniListLength < 3) break;
                
                const sniType = payload[offset + 2];
                const sniLength = this.readUint16BE(payload, offset + 3);
                
                if (sniType !== SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;
                
                // Extract the hostname
                const sni = payload.slice(offset + 5, offset + 5 + sniLength).toString('utf8');
                return sni;
            }
            
            offset += extensionLength;
        }
        
        return null;
    }
}

class HTTPHostExtractor {
    static isHTTPRequest(payload, length) {
        if (length < 4) return false;
        
        const methods = ['GET ', 'POST', 'PUT ', 'HEAD', 'DELE', 'PATC', 'OPTI'];
        const payloadStr = payload.slice(0, 4).toString('latin1');
        
        for (const method of methods) {
            if (payloadStr === method) return true;
        }
        
        return false;
    }

    static extract(payload, length) {
        if (!this.isHTTPRequest(payload, length)) {
            return null;
        }
        
        // Convert payload to string for easier searching
        const payloadStr = payload.toString('latin1');
        
        // Search for "Host: " header (case-insensitive)
        const hostIndex = payloadStr.toLowerCase().indexOf('host:');
        if (hostIndex === -1) return null;
        
        let start = hostIndex + 5;
        
        // Skip whitespace
        while (start < payloadStr.length && (payloadStr[start] === ' ' || payloadStr[start] === '\t')) {
            start++;
        }
        
        // Find end of line
        let end = start;
        while (end < payloadStr.length && payloadStr[end] !== '\r' && payloadStr[end] !== '\n') {
            end++;
        }
        
        if (end > start) {
            let host = payloadStr.substring(start, end);
            
            // Remove port if present
            const colonPos = host.indexOf(':');
            if (colonPos !== -1) {
                host = host.substring(0, colonPos);
            }
            
            return host;
        }
        
        return null;
    }
}

class DNSExtractor {
    static isDNSQuery(payload, length) {
        // Minimum DNS header is 12 bytes
        if (length < 12) return false;
        
        // Check QR bit (byte 2, bit 7) - should be 0 for query
        const flags = payload[2];
        if (flags & 0x80) return false;
        
        // Check QDCOUNT (bytes 4-5) - should be > 0
        const qdcount = (payload[4] << 8) | payload[5];
        if (qdcount === 0) return false;
        
        return true;
    }

    static extractQuery(payload, length) {
        if (!this.isDNSQuery(payload, length)) {
            return null;
        }
        
        // DNS query starts at byte 12
        let offset = 12;
        let domain = '';
        
        while (offset < length) {
            const labelLength = payload[offset];
            
            if (labelLength === 0) {
                break;
            }
            
            if (labelLength > 63) {
                break;
            }
            
            offset++;
            if (offset + labelLength > length) break;
            
            if (domain.length > 0) {
                domain += '.';
            }
            
            domain += payload.slice(offset, offset + labelLength).toString('utf8');
            offset += labelLength;
        }
        
        return domain.length > 0 ? domain : null;
    }
}

class QUICSNIExtractor {
    static extract(payload, length) {
        // QUIC packets contain TLS in CRYPTO frames
        // This is a simplified version - look for TLS Client Hello signature
        
        // QUIC Initial packets have specific format
        if (length < 50) return null;
        
        // Check for QUIC Initial packet marker
        const firstByte = payload[0];
        if ((firstByte & 0xC0) !== 0xC0) return null;
        if ((firstByte & 0x30) !== 0x00) return null;
        
        // Search for TLS Client Hello pattern (0x16 0x03 0x01+)
        for (let i = 0; i < length - 20; i++) {
            if (payload[i] === 0x16 && payload[i + 1] === 0x03) {
                // Found potential TLS record
                const tlsPayload = payload.slice(i);
                const sni = SNIExtractor.extract(tlsPayload, tlsPayload.length);
                if (sni) return sni;
            }
        }
        
        return null;
    }
}

class PayloadExtractor {
    static extractServerName(payload, protocol) {
        if (!payload || payload.length === 0) return null;
        
        // Try TLS/SNI
        let sni = SNIExtractor.extract(payload, payload.length);
        if (sni) return sni;
        
        // Try HTTP Host header
        let host = HTTPHostExtractor.extract(payload, payload.length);
        if (host) return host;
        
        // Try DNS
        let domain = DNSExtractor.extractQuery(payload, payload.length);
        if (domain) return domain;
        
        // Try QUIC
        let quicSni = QUICSNIExtractor.extract(payload, payload.length);
        if (quicSni) return quicSni;
        
        return null;
    }
}

module.exports = {
    SNIExtractor,
    HTTPHostExtractor,
    DNSExtractor,
    QUICSNIExtractor,
    PayloadExtractor
};
