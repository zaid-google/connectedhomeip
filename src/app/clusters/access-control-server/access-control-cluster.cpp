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

#include <access/AccessControl.h>

#if CHIP_CONFIG_USE_ACCESS_RESTRICTIONS
#include "ArlEncoder.h"
#include <access/AccessRestrictionProvider.h>
#endif

#include <app-common/zap-generated/cluster-objects.h>
#include <app/clusters/access-control-server/access-control-cluster.h>
#include <app/server-cluster/AttributeListBuilder.h>
#include <app/server-cluster/DefaultServerCluster.h>
#include <app/server/Server.h>

#include <app/AttributeAccessInterface.h>
#include <app/AttributeAccessInterfaceRegistry.h>
#include <app/CommandHandler.h>
#include <app/ConcreteCommandPath.h>
#include <app/EventLogging.h>
#include <app/data-model/Encode.h>
#include <app/reporting/reporting.h>
#include <app/server/AclStorage.h>
#include <app/server/Server.h>
#include <app/util/attribute-storage.h>

#include <clusters/AccessControl/ClusterId.h>
#include <clusters/AccessControl/Metadata.h>
#include <lib/support/TypeTraits.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters::AccessControl;
using namespace chip::app::Clusters::AccessControl::Attributes;
using namespace chip::DeviceLayer;
using namespace chip::Protocols::InteractionModel::Status;

namespace {
CHIP_ERROR ReadAcl(AttributeValueEncoder & aEncoder)
{
    AccessControl::EntryIterator iterator;
    AccessControl::Entry entry;
    AclStorage::EncodableEntry encodableEntry(entry);
    return aEncoder.EncodeList([&](const auto & encoder) -> CHIP_ERROR {
        for (auto & info : Server::GetInstance().GetFabricTable())
        {
            auto fabric = info.GetFabricIndex();
            ReturnErrorOnFailure(GetAccessControl().Entries(fabric, iterator));
            CHIP_ERROR err = CHIP_NO_ERROR;
            while ((err = iterator.Next(entry)) == CHIP_NO_ERROR)
            {
                ReturnErrorOnFailure(encoder.Encode(encodableEntry));
            }
            VerifyOrReturnError(err == CHIP_NO_ERROR || err == CHIP_ERROR_SENTINEL, err);
        }
        return CHIP_NO_ERROR;
    });
}

#if CHIP_CONFIG_ENABLE_ACL_EXTENSIONS
CHIP_ERROR ReadExtension(AttributeValueEncoder & aEncoder)
{
    auto & storage = Server::GetInstance().GetPersistentStorage();
    auto & fabrics = Server::GetInstance().GetFabricTable();

    return aEncoder.EncodeList([&](const auto & encoder) -> CHIP_ERROR {
        for (auto & fabric : fabrics)
        {
            uint8_t buffer[kExtensionDataMaxLength] = { 0 };
            uint16_t size                           = static_cast<uint16_t>(sizeof(buffer));
            CHIP_ERROR errStorage                   = storage.SyncGetKeyValue(
                DefaultStorageKeyAllocator::AccessControlExtensionEntry(fabric.GetFabricIndex()).KeyName(), buffer, size);
            VerifyOrReturnError(errStorage != CHIP_ERROR_BUFFER_TOO_SMALL, CHIP_ERROR_INCORRECT_STATE);
            if (errStorage == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
            {
                continue;
            }
            ReturnErrorOnFailure(errStorage);
            AccessControlCluster::Structs::AccessControlExtensionStruct::Type item = {
                .data        = ByteSpan(buffer, size),
                .fabricIndex = fabric.GetFabricIndex(),
            };
            ReturnErrorOnFailure(encoder.Encode(item));
        }
        return CHIP_NO_ERROR;
    });
}

CHIP_ERROR AccessControlAttribute::WriteExtension(const ConcreteDataAttributePath & aPath, AttributeValueDecoder & aDecoder)
{
    auto & storage = Server::GetInstance().GetPersistentStorage();

    FabricIndex accessingFabricIndex = aDecoder.AccessingFabricIndex();

    uint8_t buffer[kExtensionDataMaxLength] = { 0 };
    uint16_t size                           = static_cast<uint16_t>(sizeof(buffer));
    CHIP_ERROR errStorage                   = storage.SyncGetKeyValue(
        DefaultStorageKeyAllocator::AccessControlExtensionEntry(accessingFabricIndex).KeyName(), buffer, size);
    VerifyOrReturnError(errStorage != CHIP_ERROR_BUFFER_TOO_SMALL, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(errStorage == CHIP_NO_ERROR || errStorage == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND, errStorage);

    if (!aPath.IsListItemOperation())
    {
        DataModel::DecodableList<AccessControlCluster::Structs::AccessControlExtensionStruct::DecodableType> list;
        ReturnErrorOnFailure(aDecoder.Decode(list));

        size_t count = 0;
        ReturnErrorOnFailure(list.ComputeSize(&count));

        if (count == 0)
        {
            VerifyOrReturnError(errStorage != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND, CHIP_NO_ERROR);
            ReturnErrorOnFailure(storage.SyncDeleteKeyValue(
                DefaultStorageKeyAllocator::AccessControlExtensionEntry(accessingFabricIndex).KeyName()));
            AccessControlCluster::Structs::AccessControlExtensionStruct::Type item = {
                .data        = ByteSpan(buffer, size),
                .fabricIndex = accessingFabricIndex,
            };
            ReturnErrorOnFailure(
                LogExtensionChangedEvent(item, aDecoder.GetSubjectDescriptor(), AccessControlCluster::ChangeTypeEnum::kRemoved));
        }
        else if (count == 1)
        {
            auto iterator = list.begin();
            if (!iterator.Next())
            {
                ReturnErrorOnFailure(iterator.GetStatus());
                // If counted an item, iterator doesn't return it, iterator has no error, that's bad.
                return CHIP_ERROR_INCORRECT_STATE;
            }
            auto & item = iterator.GetValue();
            // TODO(#13590): generated code doesn't automatically handle max length so do it manually
            VerifyOrReturnError(item.data.size() <= kExtensionDataMaxLength, CHIP_IM_GLOBAL_STATUS(ConstraintError));

            ReturnErrorOnFailure(CheckExtensionEntryDataFormat(item.data));

            ReturnErrorOnFailure(
                storage.SyncSetKeyValue(DefaultStorageKeyAllocator::AccessControlExtensionEntry(accessingFabricIndex).KeyName(),
                                        item.data.data(), static_cast<uint16_t>(item.data.size())));
            ReturnErrorOnFailure(LogExtensionChangedEvent(item, aDecoder.GetSubjectDescriptor(),
                                                          errStorage == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND
                                                              ? AccessControlCluster::ChangeTypeEnum::kAdded
                                                              : AccessControlCluster::ChangeTypeEnum::kChanged));
        }
        else
        {
            return CHIP_IM_GLOBAL_STATUS(ConstraintError);
        }
    }
    else if (aPath.mListOp == ConcreteDataAttributePath::ListOperation::AppendItem)
    {
        VerifyOrReturnError(errStorage == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND, CHIP_IM_GLOBAL_STATUS(ConstraintError));
        AccessControlCluster::Structs::AccessControlExtensionStruct::DecodableType item;
        ReturnErrorOnFailure(aDecoder.Decode(item));
        // TODO(#13590): generated code doesn't automatically handle max length so do it manually
        VerifyOrReturnError(item.data.size() <= kExtensionDataMaxLength, CHIP_IM_GLOBAL_STATUS(ConstraintError));

        ReturnErrorOnFailure(CheckExtensionEntryDataFormat(item.data));

        ReturnErrorOnFailure(
            storage.SyncSetKeyValue(DefaultStorageKeyAllocator::AccessControlExtensionEntry(accessingFabricIndex).KeyName(),
                                    item.data.data(), static_cast<uint16_t>(item.data.size())));
        ReturnErrorOnFailure(
            LogExtensionChangedEvent(item, aDecoder.GetSubjectDescriptor(), AccessControlCluster::ChangeTypeEnum::kAdded));
    }
    else
    {
        return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
    }

    return CHIP_NO_ERROR;
}
#endif

#if CHIP_CONFIG_USE_ACCESS_RESTRICTIONS
CHIP_ERROR AccessControlAttribute::ReadCommissioningArl(AttributeValueEncoder & aEncoder)
{
    auto accessRestrictionProvider = GetAccessControl().GetAccessRestrictionProvider();

    return aEncoder.EncodeList([&](const auto & encoder) -> CHIP_ERROR {
        if (accessRestrictionProvider != nullptr)
        {
            auto entries = accessRestrictionProvider->GetCommissioningEntries();

            for (auto & entry : entries)
            {
                ArlEncoder::CommissioningEncodableEntry encodableEntry(entry);
                ReturnErrorOnFailure(encoder.Encode(encodableEntry));
            }
        }
        return CHIP_NO_ERROR;
    });
}

CHIP_ERROR AccessControlAttribute::ReadArl(AttributeValueEncoder & aEncoder)
{
    auto accessRestrictionProvider = GetAccessControl().GetAccessRestrictionProvider();

    return aEncoder.EncodeList([&](const auto & encoder) -> CHIP_ERROR {
        if (accessRestrictionProvider != nullptr)
        {
            for (const auto & info : Server::GetInstance().GetFabricTable())
            {
                auto fabric = info.GetFabricIndex();
                // get entries for fabric
                std::vector<AccessRestrictionProvider::Entry> entries;
                ReturnErrorOnFailure(accessRestrictionProvider->GetEntries(fabric, entries));
                for (const auto & entry : entries)
                {
                    ArlEncoder::EncodableEntry encodableEntry(entry);
                    ReturnErrorOnFailure(encoder.Encode(encodableEntry));
                }
            }
        }
        return CHIP_NO_ERROR;
    });
}

void AccessControlAttribute::MarkCommissioningRestrictionListChanged()
{
    MatterReportingAttributeChangeCallback(kRootEndpointId, AccessControlCluster::Id,
                                           AccessControl::Attributes::CommissioningARL::Id);
}

void AccessControlAttribute::MarkRestrictionListChanged(FabricIndex fabricIndex)
{
    MatterReportingAttributeChangeCallback(kRootEndpointId, AccessControlCluster::Id, AccessControl::Attributes::Arl::Id);
}

void AccessControlAttribute::OnFabricRestrictionReviewUpdate(FabricIndex fabricIndex, uint64_t token,
                                                             Optional<CharSpan> instruction, Optional<CharSpan> arlRequestFlowUrl)
{
    CHIP_ERROR err;
    ArlReviewEvent event{ .token = token, .fabricIndex = fabricIndex };

    event.instruction       = instruction;
    event.ARLRequestFlowUrl = arlRequestFlowUrl;

    EventNumber eventNumber;
    SuccessOrExit(err = LogEvent(event, kRootEndpointId, eventNumber));

    return;

exit:
    ChipLogError(DataManagement, "AccessControlCluster: review event failed: %" CHIP_ERROR_FORMAT, err.Format());
}

bool HandleReviewFabricRestrictions(
    CommandHandler * commandObj, const ConcreteCommandPath & commandPath,
    const Clusters::AccessControl::Commands::ReviewFabricRestrictions::DecodableType & commandData)
{
    if (commandPath.mEndpointId != kRootEndpointId)
    {
        ChipLogError(DataManagement, "AccessControlCluster: invalid endpoint in ReviewFabricRestrictions request");
        commandObj->AddStatus(commandPath, Protocols::InteractionModel::Status::InvalidCommand);
        return true;
    }

    uint64_t token;
    std::vector<AccessRestrictionProvider::Entry> entries;
    auto entryIter = commandData.arl.begin();
    while (entryIter.Next())
    {
        AccessRestrictionProvider::Entry entry;
        entry.fabricIndex    = commandObj->GetAccessingFabricIndex();
        entry.endpointNumber = entryIter.GetValue().endpoint;
        entry.clusterId      = entryIter.GetValue().cluster;

        auto restrictionIter = entryIter.GetValue().restrictions.begin();
        while (restrictionIter.Next())
        {
            AccessRestrictionProvider::Restriction restriction;
            if (ArlEncoder::Convert(restrictionIter.GetValue().type, restriction.restrictionType) != CHIP_NO_ERROR)
            {
                ChipLogError(DataManagement, "AccessControlCluster: invalid restriction type conversion");
                commandObj->AddStatus(commandPath, Protocols::InteractionModel::Status::InvalidCommand);
                return true;
            }

            if (!restrictionIter.GetValue().id.IsNull())
            {
                restriction.id.SetValue(restrictionIter.GetValue().id.Value());
            }
            entry.restrictions.push_back(restriction);
        }

        if (restrictionIter.GetStatus() != CHIP_NO_ERROR)
        {
            ChipLogError(DataManagement, "AccessControlCluster: invalid ARL data");
            commandObj->AddStatus(commandPath, Protocols::InteractionModel::Status::InvalidCommand);
            return true;
        }

        entries.push_back(entry);
    }

    if (entryIter.GetStatus() != CHIP_NO_ERROR)
    {
        ChipLogError(DataManagement, "AccessControlCluster: invalid ARL data");
        commandObj->AddStatus(commandPath, Protocols::InteractionModel::Status::InvalidCommand);
        return true;
    }

    CHIP_ERROR err = GetAccessControl().GetAccessRestrictionProvider()->RequestFabricRestrictionReview(
        commandObj->GetAccessingFabricIndex(), entries, token);

    if (err == CHIP_NO_ERROR)
    {
        Clusters::AccessControl::Commands::ReviewFabricRestrictionsResponse::Type response;
        response.token = token;
        commandObj->AddResponse(commandPath, response);
    }
    else
    {
        ChipLogError(DataManagement, "AccessControlCluster: restriction review failed: %" CHIP_ERROR_FORMAT, err.Format());
        commandObj->AddStatus(commandPath, Protocols::InteractionModel::ClusterStatusCode(err));
    }

    return true;
}
#endif
}

namespace chip {
namespace app {
namespace Clusters {

DataModel::ActionReturnStatus AccessControlCluster::ReadAttribute(const DataModel::ReadAttributeRequest & request,
                                            AttributeValueEncoder & encoder) {
    switch (request.path.mAttributeId)
    {
    case AccessControl::Attributes::Acl::Id:
        return ReadAcl(encoder);
#if CHIP_CONFIG_ENABLE_ACL_EXTENSIONS
    case AccessControl::Attributes::Extension::Id:
        return ReadExtension(encoder);
#endif // CHIP_CONFIG_ENABLE_ACL_EXTENSIONS
    case AccessControl::Attributes::SubjectsPerAccessControlEntry::Id: {
        size_t value = 0;
        ReturnErrorOnFailure(GetAccessControl().GetMaxSubjectsPerEntry(value));
        return encoder.Encode(static_cast<uint16_t>(value));
    }
    case AccessControl::Attributes::TargetsPerAccessControlEntry::Id: {
        size_t value = 0;
        ReturnErrorOnFailure(GetAccessControl().GetMaxTargetsPerEntry(value));
        return encoder.Encode(static_cast<uint16_t>(value));
    }
    case AccessControl::Attributes::AccessControlEntriesPerFabric::Id: {
        size_t value = 0;
        ReturnErrorOnFailure(GetAccessControl().GetMaxEntriesPerFabric(value));
        return encoder.Encode(static_cast<uint16_t>(value));
    }
#if CHIP_CONFIG_USE_ACCESS_RESTRICTIONS
    case AccessControl::Attributes::CommissioningARL::Id:
        return ReadCommissioningArl(encoder);
    case AccessControl::Attributes::Arl::Id:
        return ReadArl(encoder);
#endif
    case AccessControl::Attributes::FeatureMap::Id: {
        uint32_t featureMap = 0;

#if CHIP_CONFIG_USE_ACCESS_RESTRICTIONS
        featureMap |= to_underlying(AccessControlCluster::Feature::kManagedDevice);
#endif // CHIP_CONFIG_USE_ACCESS_RESTRICTIONS

#if CHIP_CONFIG_ENABLE_ACL_EXTENSIONS
        featureMap |= to_underlying(AccessControlCluster::Feature::kExtension);
#endif // CHIP_CONFIG_ENABLE_ACL_EXTENSIONS

        return encoder.Encode(featureMap);
    }
    case AccessControl::Attributes::ClusterRevision::Id:
        return encoder.Encode(AccessControl::kRevision);
    }

    return CHIP_NO_ERROR;
}

DataModel::ActionReturnStatus AccessControlCluster::WriteAttribute(const DataModel::WriteAttributeRequest & request,
                                                                        AttributeValueDecoder & decoder) {
    switch (request.path.mAttributeId)
    {
    case Acl::Id: {
        return NotifyAttributeChangedIfSuccess();
    }
    case Extension::Id: {
        return NotifyAttributeChangedIfSuccess();
    }
    default:
        return Protocols::InteractionModel::Status::UnsupportedWrite;
    }
}

std::optional<DataModel::ActionReturnStatus> AccessControlCluster::InvokeCommand(const DataModel::InvokeRequest & request,
                                                               chip::TLV::TLVReader & input_arguments,
                                                               CommandHandler * handler) {
    switch (request.path.mCommandId)
    {
#if CHIP_CONFIG_USE_ACCESS_RESTRICTIONS
        case AccessControl::Commands::ReviewFabricRestrictions::Id: {
            AccessControl::Commands::ReviewFabricRestrictions::DecodableType data;
            ReturnErrorOnFailure(data.Decode(input_arguments, handler->GetAccessingFabricIndex()));
            return HandleReviewFabricRestrictions(handler, request.path, data);
        }
#endif
        default:
            return Protocols::InteractionModel::Status::UnsupportedCommand;
    }
}

}
}
}
