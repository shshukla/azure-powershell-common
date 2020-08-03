﻿// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Linq;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;

namespace Microsoft.Azure.Management.ResourceManager.Version2019_06_01.Models.Utilities
{
    public static class SubscriptionExtensions
    {
        public static AzureSubscription ToAzureSubscription(this Subscription other, IAzureAccount account, IAzureEnvironment environment, string retrievedByTenant)
        {
            var subscription = new AzureSubscription() {
                Id = other.SubscriptionId,
                Name = other.DisplayName,
                State = other.State?.ToSerializedValue()
            };
            subscription.SetAccount(account?.Id);
            subscription.SetEnvironment(environment != null ? environment.Name : EnvironmentName.AzureCloud);
            subscription.SetHomeTenant(other.TenantId ?? retrievedByTenant);
            if (other.ManagedByTenants != null && other.ManagedByTenants.Any())
            {
                subscription.SetManagedByTenants(other.ManagedByTenants.Select(t => t.TenantId).ToArray());
            }
            subscription.SetTenant(retrievedByTenant);
            return subscription;
        }
    }
}
