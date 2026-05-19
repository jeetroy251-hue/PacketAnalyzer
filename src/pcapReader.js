/**
 * PCAP Reader - Read and parse PCAP files
 * Converted from C++ to JavaScript
 */

const fs = require('fs');
const path = require('path');
const { PcapGlobalHeader, PcapPacketHeader } = require('./types');

class RawPacket {
    constructor() {
        this.header = new PcapPacketHeader();
        this.data = Buffer.alloc(0);
    }
}

class PcapReader {
    constructor() {
        this.file = null;
        this.fileHandle = null;
        this.global_header = null;
        this.currentPosition = 0;
        this.fileSize = 0;
        this.isBigEndian = false;
    }

    async open(filename) {
        try {
            // Check if file exists
            if (!fs.existsSync(filename)) {
                console.error(`[PcapReader] Error: File not found: ${filename}`);
                return false;
            }

            this.file = filename;
            this.fileHandle = fs.openSync(filename, 'r');
            this.fileSize = fs.statSync(filename).size;

            // Read global header (24 bytes)
            if (this.fileSize < 24) {
                console.error('[PcapReader] Error: File too small for PCAP header');
                fs.closeSync(this.fileHandle);
                return false;
            }

            const headerBuffer = Buffer.alloc(24);
            fs.readSync(this.fileHandle, headerBuffer, 0, 24, 0);

            this.global_header = PcapGlobalHeader.fromBuffer(headerBuffer);

            // Check magic number to detect byte order
            if (this.global_header.magic_number === 0xa1b2c3d4) {
                this.isBigEndian = false;
            } else if (this.global_header.magic_number === 0xd4c3b2a1) {
                this.isBigEndian = true;
            } else {
                console.error('[PcapReader] Error: Invalid PCAP magic number');
                fs.closeSync(this.fileHandle);
                return false;
            }

            this.currentPosition = 24;
            console.log(`[PcapReader] Opened ${path.basename(filename)} successfully`);
            return true;

        } catch (error) {
            console.error(`[PcapReader] Error opening file: ${error.message}`);
            return false;
        }
    }

    readNextPacket(rawPacket) {
        try {
            // Check if we're at end of file
            if (this.currentPosition >= this.fileSize) {
                return false;
            }

            // Check if we have enough data for packet header
            if (this.currentPosition + 16 > this.fileSize) {
                return false;
            }

            // Read packet header (16 bytes)
            const headerBuffer = Buffer.alloc(16);
            fs.readSync(this.fileHandle, headerBuffer, 0, 16, this.currentPosition);
            this.currentPosition += 16;

            rawPacket.header = this.isBigEndian ? 
                this.readPacketHeaderBE(headerBuffer) :
                PcapPacketHeader.fromBuffer(headerBuffer);

            // Read packet data
            if (this.currentPosition + rawPacket.header.incl_len > this.fileSize) {
                console.warn('[PcapReader] Warning: Truncated packet at end of file');
                return false;
            }

            rawPacket.data = Buffer.alloc(rawPacket.header.incl_len);
            fs.readSync(this.fileHandle, rawPacket.data, 0, rawPacket.header.incl_len, this.currentPosition);
            this.currentPosition += rawPacket.header.incl_len;

            return true;

        } catch (error) {
            console.error(`[PcapReader] Error reading packet: ${error.message}`);
            return false;
        }
    }

    readPacketHeaderBE(buffer) {
        const header = new PcapPacketHeader();
        header.ts_sec = buffer.readUInt32BE(0);
        header.ts_usec = buffer.readUInt32BE(4);
        header.incl_len = buffer.readUInt32BE(8);
        header.orig_len = buffer.readUInt32BE(12);
        return header;
    }

    close() {
        try {
            if (this.fileHandle !== null) {
                fs.closeSync(this.fileHandle);
                this.fileHandle = null;
                console.log('[PcapReader] File closed');
            }
        } catch (error) {
            console.error(`[PcapReader] Error closing file: ${error.message}`);
        }
    }

    getGlobalHeader() {
        return this.global_header;
    }

    getFileSize() {
        return this.fileSize;
    }

    getCurrentPosition() {
        return this.currentPosition;
    }
}

module.exports = { PcapReader, RawPacket };
