//-----------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------

using System;

namespace Microsoft.Azure.Commands.Common.Authentication
{
    public class CustomAuthResult
    {
        public string AccessToken { get; set; }

        public DateTime ExpiresOn { get; set; }

        public string TokenType { get; set; }
    }
}
