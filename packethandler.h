/*
 * WhatPulse External PCap Service - Packet Handler Interface
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

#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include "pcapcapturethread.h" // For PacketData

/**
 * Interface for handling captured packets
 * This allows capture threads to work with any service that can handle packets
 */
class IPacketHandler
{
public:
    virtual ~IPacketHandler() = default;
    virtual void onPacketCaptured(const PacketData &packet) = 0;
};

#endif // PACKETHANDLER_H
