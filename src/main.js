#!/usr/bin/env node

/**
 * DPI Engine - Main Entry Point
 * Deep Packet Inspection System in JavaScript
 * 
 * Converted from C++ to JavaScript
 * Maintains same architecture and logic
 */

const { DPIEngine } = require('./dpiEngine');
const { stringToAppType, AppType } = require('./types');
const fs = require('fs');
const path = require('path');

async function main() {
    console.log('\n================================');
    console.log('  Deep Packet Inspection Engine');
    console.log('  JavaScript Version');
    console.log('================================\n');
    
    // Get command line arguments
    const args = process.argv.slice(2);
    
    let inputFile = 'test_dpi.pcap';
    let outputFile = 'output.pcap';
    let rulesFile = '';
    let numLbs = 2;
    let fpsPerLb = 4;
    let blockApps = [];
    let blockIps = [];
    let blockDomains = [];
    
    // Parse arguments
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-i' || args[i] === '--input') {
            inputFile = args[++i];
        } else if (args[i] === '-o' || args[i] === '--output') {
            outputFile = args[++i];
        } else if (args[i] === '-r' || args[i] === '--rules') {
            rulesFile = args[++i];
        } else if (args[i] === '--block-app') {
            blockApps.push(args[++i]);
        } else if (args[i] === '--block-ip') {
            blockIps.push(args[++i]);
        } else if (args[i] === '--block-domain') {
            blockDomains.push(args[++i]);
        } else if (args[i] === '--lbs') {
            numLbs = parseInt(args[++i]);
        } else if (args[i] === '--fps-per-lb') {
            fpsPerLb = parseInt(args[++i]);
        } else if (args[i] === '-h' || args[i] === '--help') {
            printHelp();
            process.exit(0);
        }
    }
    
    // Check if input file exists
    if (!fs.existsSync(inputFile)) {
        console.error(`Error: Input file not found: ${inputFile}`);
        console.error('Usage: node main.js -i <input.pcap> -o <output.pcap> [options]');
        process.exit(1);
    }
    
    // Create DPI Engine
    const config = {
        num_load_balancers: numLbs,
        fps_per_lb: fpsPerLb,
        rules_file: rulesFile
    };
    
    const engine = new DPIEngine(config);
    await engine.initialize();

    // Apply direct block options after initialization
    for (const appName of blockApps) {
        const appType = stringToAppType(appName);
        if (appType === AppType.UNKNOWN && appName.toString().trim().toUpperCase() !== 'UNKNOWN') {
            console.warn(`[Warning] Unknown block-app name: ${appName}`);
            continue;
        }
        engine.blockApp(appType);
    }
    for (const ip of blockIps) {
        engine.blockIP(ip);
    }
    for (const domain of blockDomains) {
        engine.blockDomain(domain);
    }
    
    // Process file
    const startTime = Date.now();
    
    try {
        const success = await engine.processFile(inputFile, outputFile);
        
        const endTime = Date.now();
        const duration = ((endTime - startTime) / 1000).toFixed(2);
        
        if (success) {
            console.log(`\n✓ Processing completed in ${duration} seconds`);
            console.log(`✓ Output saved to: ${outputFile}`);
            process.exit(0);
        } else {
            console.error('✗ Processing failed');
            process.exit(1);
        }
    } catch (error) {
        console.error(`✗ Error: ${error.message}`);
        process.exit(1);
    }
}

function printHelp() {
    console.log(`
Deep Packet Inspection Engine - JavaScript Version

Usage: node main.js [options]

Options:
  -i, --input <file>        Input PCAP file (default: test_dpi.pcap)
  -o, --output <file>       Output PCAP file (default: output.pcap)
  -r, --rules <file>        Rules file to load
  --lbs <num>               Number of load balancers (default: 2)
  --fps-per-lb <num>        Fast paths per load balancer (default: 4)
  --block-app <name>        Block an application by name (repeatable)
  --block-ip <ip>           Block a source IP address (repeatable)
  --block-domain <domain>   Block a domain or hostname (repeatable)
  -h, --help                Show this help message

Examples:
  # Basic usage
  node main.js -i input.pcap -o output.pcap
  
  # With rules
  node main.js -i input.pcap -o output.pcap -r rules.txt
  
  # Block applications, IPs, and domains directly
  node main.js -i input.pcap -o output.pcap --block-app YouTube --block-app TikTok --block-ip 192.168.1.50 --block-domain facebook
  
  # Custom threading
  node main.js -i input.pcap -o output.pcap --lbs 4 --fps-per-lb 8

About:
  This is a JavaScript conversion of the C++ DPI (Deep Packet Inspection) engine.
  It maintains the same architecture, logic, and output format as the original C++ version.
  
  The engine processes PCAP files, analyzing network packets and applying filtering rules
  based on IPs, domains, applications, and ports.
    `);
}

// Run main
if (require.main === module) {
    main().catch(error => {
        console.error('Unhandled error:', error);
        process.exit(1);
    });
}

module.exports = { main };
