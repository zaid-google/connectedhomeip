/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *    Copyright (c) 2013-2017 Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      This file implements the CHIP Connection object that maintains a UDP connection.
 */
#include <transport/raw/UDP.h>

#include <lib/support/CHIPFaultInjection.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <transport/raw/GroupcastTesting.h>
#include <transport/raw/MessageHeader.h>

#include <inttypes.h>

namespace chip {
namespace Transport {

CHIP_ERROR UDP::Init(UdpListenParameters & params)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    if (mState != State::kNotReady)
    {
        Close();
    }

    mEndPointManager = params.GetEndPointManager();
    err = mEndPointManager->NewEndPoint(mUDPEndPoint);
    SuccessOrExit(err);

    mUDPEndPoint->SetNativeParams(params.GetNativeParams());

    ChipLogDetail(Inet, "UDP::Init bind&listen port=%d", params.GetListenPort());

    err = mUDPEndPoint->Bind(params.GetAddressType(), Inet::IPAddress::Any, params.GetListenPort(), params.GetInterfaceId());
    SuccessOrExit(err);

    err = mUDPEndPoint->Listen(OnUdpReceive, OnUdpError, this);
    SuccessOrExit(err);

    mUDPEndpointType = params.GetAddressType();

    mState = State::kInitialized;

    ChipLogDetail(Inet, "UDP::Init bound to port=%d", mUDPEndPoint->GetBoundPort());

exit:
    if (err != CHIP_NO_ERROR)
    {
        ChipLogProgress(Inet, "Failed to initialize Udp transport: %" CHIP_ERROR_FORMAT, err.Format());
        mUDPEndPoint.Release();
    }

    return err;
}

uint16_t UDP::GetBoundPort()
{
    VerifyOrDie(mUDPEndPoint);
    return mUDPEndPoint->GetBoundPort();
}

void UDP::Close()
{
    for (size_t i = 0; i < mMulticastGroupCount; i++)
    {
        if (mMulticastGroupEndPoints[i].mEndPoint)
        {
            mMulticastGroupEndPoints[i].mEndPoint->Close();
            mMulticastGroupEndPoints[i].mEndPoint.Release();
        }
    }
    mMulticastGroupCount = 0;

    mUDPEndPoint.Release();
    mState = State::kNotReady;
}

CHIP_ERROR UDP::SendMessage(const Transport::PeerAddress & address, System::PacketBufferHandle && msgBuf)
{
    VerifyOrReturnError(address.GetTransportType() == Type::kUdp, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(mState == State::kInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(mUDPEndPoint, CHIP_ERROR_INCORRECT_STATE);

    Inet::IPPacketInfo addrInfo;
    addrInfo.Clear();

    addrInfo.DestAddress = address.GetIPAddress();
    addrInfo.DestPort    = address.GetPort();
    addrInfo.Interface   = address.GetInterface();

    // Drop the message and return. Free the buffer.
    CHIP_FAULT_INJECT(FaultInjection::kFault_DropOutgoingUDPMsg, msgBuf = nullptr; return CHIP_ERROR_CONNECTION_ABORTED;);

    return mUDPEndPoint->SendMsg(&addrInfo, std::move(msgBuf));
}

void UDP::OnUdpReceive(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && buffer, const Inet::IPPacketInfo * pktInfo)
{
    CHIP_ERROR err          = CHIP_NO_ERROR;
    UDP * udp               = reinterpret_cast<UDP *>(endPoint->mAppState);
    PeerAddress peerAddress = PeerAddress::UDP(pktInfo->SrcAddress, pktInfo->SrcPort, pktInfo->Interface);

    auto & testing = Groupcast::GetTesting();
    if (testing.IsEnabled())
    {
        PeerAddress destAddress = PeerAddress::UDP(pktInfo->DestAddress, pktInfo->DestPort, pktInfo->Interface);
        testing.SetSourceIpAddress(peerAddress.GetIPAddress());
        testing.SetDestinationIpAddress(destAddress.GetIPAddress());
    }

    CHIP_FAULT_INJECT(FaultInjection::kFault_DropIncomingUDPMsg, buffer = nullptr; return;);

    udp->HandleMessageReceived(peerAddress, std::move(buffer));

    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Inet, "Failed to receive UDP message: %" CHIP_ERROR_FORMAT, err.Format());
    }
}

void UDP::OnUdpError(Inet::UDPEndPoint * endPoint, CHIP_ERROR err, const Inet::IPPacketInfo * pktInfo)
{
    ChipLogError(Inet, "Failed to receive UDP message: %" CHIP_ERROR_FORMAT, err.Format());
}

CHIP_ERROR UDP::MulticastGroupJoinLeave(const Transport::PeerAddress & address, bool join)
{
    char addressStr[Transport::PeerAddress::kMaxToStringSize];
    address.ToString(addressStr, Transport::PeerAddress::kMaxToStringSize);

    const Inet::IPAddress & groupAddr = address.GetIPAddress();
    Inet::InterfaceId intfId          = mUDPEndPoint ? mUDPEndPoint->GetBoundInterface() : Inet::InterfaceId::Null();

    if (join)
    {
        ChipLogProgress(Inet, "Joining Multicast Group with address %s", addressStr);

        // If unicast listening port is already CHIP_PORT (5540), join directly on mUDPEndPoint
        if (mUDPEndPoint && mUDPEndPoint->GetBoundPort() == CHIP_PORT)
        {
            return mUDPEndPoint->JoinMulticastGroup(intfId, groupAddr);
        }

        // If unicast listening port is not CHIP_PORT (5540), create a dedicated listener on port 5540
        // that is specific to the group address.
        for (size_t i = 0; i < mMulticastGroupCount; i++)
        {
            if (mMulticastGroupEndPoints[i].mAddress == groupAddr)
            {
                return CHIP_NO_ERROR;
            }
        }

        VerifyOrReturnError(mMulticastGroupCount < kMaxMulticastGroups, CHIP_ERROR_NO_MEMORY);
        VerifyOrReturnError(mEndPointManager != nullptr, CHIP_ERROR_INCORRECT_STATE);

        Inet::UDPEndPointHandle groupEndPoint;
        ReturnErrorOnFailure(mEndPointManager->NewEndPoint(groupEndPoint));

        // Bind specifically to groupAddr (multicast IPv6 address) on port 5540 (CHIP_PORT).
        // This ensures the socket ONLY matches multicast packets sent to groupAddr,
        // preventing unicast traffic from being load-balanced onto this socket.
        CHIP_ERROR err = groupEndPoint->Bind(mUDPEndpointType, groupAddr, CHIP_PORT, intfId);
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Inet, "Failed to bind group multicast endpoint to port %d: %" CHIP_ERROR_FORMAT, CHIP_PORT, err.Format());
            groupEndPoint.Release();
            return err;
        }

        err = groupEndPoint->JoinMulticastGroup(intfId, groupAddr);
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Inet, "Failed to join group multicast group: %" CHIP_ERROR_FORMAT, err.Format());
            groupEndPoint.Release();
            return err;
        }

        err = groupEndPoint->Listen(OnUdpReceive, OnUdpError, this);
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Inet, "Failed to listen on group multicast endpoint: %" CHIP_ERROR_FORMAT, err.Format());
            groupEndPoint.Release();
            return err;
        }

        mMulticastGroupEndPoints[mMulticastGroupCount++] = { groupAddr, std::move(groupEndPoint) };
        return CHIP_NO_ERROR;
    }
    else
    {
        ChipLogProgress(Inet, "Leaving Multicast Group with address %s", addressStr);

        if (mUDPEndPoint && mUDPEndPoint->GetBoundPort() == CHIP_PORT)
        {
            return mUDPEndPoint->LeaveMulticastGroup(intfId, groupAddr);
        }

        for (size_t i = 0; i < mMulticastGroupCount; i++)
        {
            if (mMulticastGroupEndPoints[i].mAddress == groupAddr)
            {
                if (mMulticastGroupEndPoints[i].mEndPoint)
                {
                    CHIP_ERROR leaveErr = mMulticastGroupEndPoints[i].mEndPoint->LeaveMulticastGroup(intfId, groupAddr);
                    if (leaveErr != CHIP_NO_ERROR)
                    {
                        ChipLogError(Inet, "Failed to leave multicast group: %" CHIP_ERROR_FORMAT, leaveErr.Format());
                    }
                    mMulticastGroupEndPoints[i].mEndPoint->Close();
                    mMulticastGroupEndPoints[i].mEndPoint.Release();
                }

                for (size_t j = i; j < mMulticastGroupCount - 1; j++)
                {
                    mMulticastGroupEndPoints[j] = std::move(mMulticastGroupEndPoints[j + 1]);
                }
                mMulticastGroupCount--;
                break;
            }
        }

        return CHIP_NO_ERROR;
    }
}

} // namespace Transport
} // namespace chip
