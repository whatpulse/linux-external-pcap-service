/*
 * WhatPulse External PCap Service
 * 
 * Copyright (c) 2025 WhatPulse. All rights reserved.
 * 
 * Licensed under CC BY-NC 4.0 with additional terms.
 * See LICENSE file for complete terms and conditions.
 * 
 * NOTICE: This software integrates with WhatPulse services. Reverse engineering
 * the communication protocol or tampering with data transmission is prohibited.
 * 
 * For licensing questions: support@whatpulse.org
 */

#include <iostream>
#include <string>
#include <cstring>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "pcapservice.h"

// Global service instance for signal handler
PcapService* g_service = nullptr;

void printUsage(const char* programName) {
    std::cout << "WhatPulse PCap Service v" << PCAP_SERVICE_VERSION << "\n\n";
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --host HOST        WhatPulse host to connect to (default: localhost)\n";
    std::cout << "  -p, --port PORT        WhatPulse port to connect to (default: 3499)\n";
    std::cout << "  -i, --interface IFACE  Network interface to monitor (default: all)\n";
    std::cout << "  -v, --verbose          Enable verbose logging\n";
    std::cout << "  --help                 Display this help and exit\n";
    std::cout << "  --version              Output version information and exit\n\n";
    std::cout << "This service requires root privileges to capture network packets.\n";
}

void printVersion() {
    std::cout << "WhatPulse PCap Service v" << PCAP_SERVICE_VERSION << "\n";
    std::cout << "External PCap service for WhatPulse network monitoring\n";
}

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down gracefully..." << std::endl;
    if (g_service) {
        g_service->stop();
    }
    // Exit immediately after stopping the service
    exit(0);
}

int main(int argc, char *argv[])
{
    std::string host = "localhost";
    uint16_t port = 3499;
    std::string interface = "";
    bool verbose = false;
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"host",      required_argument, 0, 'h'},
        {"port",      required_argument, 0, 'p'},
        {"interface", required_argument, 0, 'i'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 1},
        {"version",   no_argument,       0, 2},
        {0, 0, 0, 0}
    };
    
    int c;
    int option_index = 0;
    
    while ((c = getopt_long(argc, argv, "h:p:i:v", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = static_cast<uint16_t>(std::stoul(optarg));
                break;
            case 'i':
                interface = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 1:
                printUsage(argv[0]);
                return 0;
            case 2:
                printVersion();
                return 0;
            case '?':
                printUsage(argv[0]);
                return 1;
            default:
                break;
        }
    }
    
    if (verbose) {
        std::cout << "WhatPulse PCap Service starting..." << std::endl;
        std::cout << "Target host: " << host << std::endl;
        std::cout << "Target port: " << port << std::endl;
        std::cout << "Interface: " << (interface.empty() ? "all" : interface) << std::endl;
    }
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    PcapService service;
    g_service = &service;
    
    if (!service.initialize(host, port, interface, verbose)) {
        std::cerr << "Failed to initialize PCap service" << std::endl;
        return 1;
    }
    
    if (!service.start()) {
        std::cerr << "Failed to start PCap service" << std::endl;
        return 1;
    }
    
    if (verbose) {
        std::cout << "Service started successfully. Press Ctrl+C to stop." << std::endl;
    }
    
    // Keep the service running
    service.run();
    
    return 0;
}
