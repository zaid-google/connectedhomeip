/**
 *
 *    Copyright (c) 2025 Project CHIP Authors
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

#include <app/clusters/general-diagnostics-server/general-diagnostics-cluster.h>
#include <app/clusters/general-diagnostics-server/general-diagnostics-logic.h>
#include <app/CommandResponseHelper.h>
#include <app/server/Server.h>
#include <app/server-cluster/DefaultServerCluster.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <clusters/GeneralDiagnostics/ClusterId.h>

namespace chip {
namespace app {
namespace Clusters {

DataModel::ActionReturnStatus GeneralDiagnosticsCluster::ReadAttribute(const DataModel::ReadAttributeRequest & request, AttributeValueEncoder & encoder) {
    using namespace GeneralDiagnostics::Attributes;
    switch (request.path.mAttributeId)
    {
    case NetworkInterfaces::Id: {
        return mLogic.ReadNetworkInterfaces(encoder);
    }
    case ActiveHardwareFaults::Id: {
        chip::DeviceLayer::GeneralFaults<DeviceLayer::kMaxHardwareFaults> valueList;
        CHIP_ERROR err = mLogic.GetActiveHardwareFaults(valueList);
        return EncodeListOfValues(valueList, err, encoder);
    }
    case ActiveRadioFaults::Id: {
        chip::DeviceLayer::GeneralFaults<DeviceLayer::kMaxRadioFaults> valueList;
        CHIP_ERROR err = mLogic.GetActiveRadioFaults(valueList);
        return EncodeListOfValues(valueList, err, encoder);
    }
    case ActiveNetworkFaults::Id: {
        chip::DeviceLayer::GeneralFaults<DeviceLayer::kMaxNetworkFaults> valueList;
        CHIP_ERROR err = mLogic.GetActiveNetworkFaults(valueList);
        return EncodeListOfValues(valueList, err, encoder);
    }
    case RebootCount::Id: {
        uint16_t value;
        CHIP_ERROR err = mLogic.GetRebootCount(value);
        return EncodeValue(value, err, encoder);
    }
    case UpTime::Id: {
        System::Clock::Seconds64 system_time_seconds =
            std::chrono::duration_cast<System::Clock::Seconds64>(chip::Server::GetInstance().TimeSinceInit());
        return encoder.Encode(static_cast<uint64_t>(system_time_seconds.count()));
    }
    case TotalOperationalHours::Id: {
        uint32_t value;
        CHIP_ERROR err = mLogic.GetTotalOperationalHours(value);
        return EncodeValue(value, err, encoder);
    }
    case BootReason::Id: {
        chip::app::Clusters::GeneralDiagnostics::BootReasonEnum value;
        CHIP_ERROR err = mLogic.GetBootReason(value);
        return EncodeValue(value, err, encoder);
    }
    case TestEventTriggersEnabled::Id: {
        bool isTestEventTriggersEnabled = IsTestEventTriggerEnabled();
        return encoder.Encode(isTestEventTriggersEnabled);
    }
        // Note: Attribute ID 0x0009 was removed (#30002).

    case FeatureMap::Id: {
        uint32_t features = 0;

#if CHIP_CONFIG_MAX_PATHS_PER_INVOKE > 1
        features |= to_underlying(Clusters::GeneralDiagnostics::Feature::kDataModelTest);
#endif // CHIP_CONFIG_MAX_PATHS_PER_INVOKE > 1

        return encoder.Encode(features);
    }

    case ClusterRevision::Id: {
        return encoder.Encode(kCurrentClusterRevision);
    }
    }
    return CHIP_NO_ERROR;    
}

std::optional<DataModel::ActionReturnStatus> GeneralDiagnosticsCluster::InvokeCommand(const DataModel::InvokeRequest & request, chip::TLV::TLVReader & input_arguments, CommandHandler * handler) {
    using namespace GeneralDiagnostics::Commands;

    switch (request.path.mCommandId)
    {
    case TestEventTrigger::Id: {
        TestEventTrigger::DecodableType request_data;
        ReturnErrorOnFailure(request_data.Decode(input_arguments));
        return mLogic.HandleTestEventTrigger(request_data);
    }
    case TimeSnapshot::Id: {
        TimeSnapshot::DecodableType request_data;
        ReturnErrorOnFailure(request_data.Decode(input_arguments));
        return mLogic.HandleTimeSnapshot(*handler, request.path, request_data);
    }
    case PayloadTestRequest::Id: {
        PayloadTestRequest::DecodableType request_data;
        ReturnErrorOnFailure(request_data.Decode(input_arguments));
        return mLogic.HandlePayloadTestRequest(*handler, request.path, request_data);
    }
    }
}

void GeneralDiagnosticsCluster::OnDeviceReboot(GeneralDiagnostics::BootReasonEnum bootReason) {
    ReportAttributeOnAllEndpoints(GeneralDiagnostics::Attributes::BootReason::Id);

    // GeneralDiagnostics cluster should exist only for endpoint 0.
    VerifyOrReturn(mContext != nullptr);
    GeneralDiagnostics::Events::BootReason::Type event{ bootReason };
    EventNumber eventNumber;

    (void) mContext->interactionContext->eventsGenerator->GenerateEvent(event, kRootEndpointId);
}

void GeneralDiagnosticsCluster::OnHardwareFaultsDetect(const DeviceLayer::GeneralFaults<DeviceLayer::kMaxHardwareFaults> & previous,
                            const DeviceLayer::GeneralFaults<DeviceLayer::kMaxHardwareFaults> & current) {
    VerifyOrReturn(mContext != nullptr);

    // If General Diagnostics cluster is implemented on this endpoint
    NotifyAttributeChanged(GeneralDiagnostics::Attributes::ActiveHardwareFaults::Id);

    // Record HardwareFault event
    EventNumber eventNumber;
    DataModel::List<const HardwareFaultEnum> currentList(reinterpret_cast<const HardwareFaultEnum *>(current.data()),
                                                            current.size());
    DataModel::List<const HardwareFaultEnum> previousList(reinterpret_cast<const HardwareFaultEnum *>(previous.data()),
                                                            previous.size());
    GeneralDiagnostics::Events::HardwareFaultChange::Type event{ currentList, previousList };

    (void) mContext->interactionContext->eventsGenerator->GenerateEvent(event, kRootEndpointId);
}

void GeneralDiagnosticsCluster::OnRadioFaultsDetect(const DeviceLayer::GeneralFaults<DeviceLayer::kMaxRadioFaults> & previous,
                            const DeviceLayer::GeneralFaults<DeviceLayer::kMaxRadioFaults> & current) {
    // If General Diagnostics cluster is implemented on this endpoint
    NotifyAttributeChanged(GeneralDiagnostics::Attributes::ActiveRadioFaults::Id);

    // Record RadioFault event
    EventNumber eventNumber;
    DataModel::List<const RadioFaultEnum> currentList(reinterpret_cast<const RadioFaultEnum *>(current.data()), current.size());
    DataModel::List<const RadioFaultEnum> previousList(reinterpret_cast<const RadioFaultEnum *>(previous.data()),
                                                        previous.size());
    GeneralDiagnostics::Events::RadioFaultChange::Type event{ currentList, previousList };

    (void) mContext->interactionContext->eventsGenerator->GenerateEvent(event, kRootEndpointId);
}

void GeneralDiagnosticsCluster::OnNetworkFaultsDetect(const DeviceLayer::GeneralFaults<DeviceLayer::kMaxNetworkFaults> & previous,
                            const DeviceLayer::GeneralFaults<DeviceLayer::kMaxNetworkFaults> & current) {
                                
}

template <typename T>
CHIP_ERROR GeneralDiagnosticsCluster::EncodeValue(T value, CHIP_ERROR readError, AttributeValueEncoder & encoder) {
    if (readError == CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE)
    {
        value = {};
    }
    else if (readError != CHIP_NO_ERROR)
    {
        return readError;
    }
    return encoder.Encode(value);
}

template <typename T>
CHIP_ERROR GeneralDiagnosticsCluster::EncodeListOfValues(T valueList, CHIP_ERROR readError, AttributeValueEncoder & encoder){
    if (readError == CHIP_NO_ERROR) {
        readError = encoder.EncodeList([&valueList](const auto & encoder) -> CHIP_ERROR {
            for (auto value : valueList) {
                ReturnErrorOnFailure(encoder.Encode(value));
            }

            return CHIP_NO_ERROR;
        });
    } else {
        readError = encoder.EncodeEmptyList()
    }

    return readError;
}

bool GeneralDiagnosticsCluster::IsTestEventTriggerEnabled()
{
    auto * triggerDelegate = chip::Server::GetInstance().GetTestEventTriggerDelegate();
    if (triggerDelegate == nullptr)
    {
        return false;
    }
    uint8_t zeroByteSpanData[TestEventTriggerDelegate::kEnableKeyLength] = { 0 };
    if (triggerDelegate->DoesEnableKeyMatch(ByteSpan(zeroByteSpanData)))
    {
        return false;
    }
    return true;
}

}
}
}