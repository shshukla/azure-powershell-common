//-----------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------

namespace Microsoft.Azure.Commands.Common.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// A utility used for encrypting and decrypting content using JSON Web Encryption.
    /// </summary>
    public static class AadTokenProvider
    {
        public static async Task<CustomAuthResult> AcquireTokenAsync(string resource, string adEndpoint, string tenantId, string clientId, X509Certificate2 certificate)
        {
            var tokenUri = new Uri($"{adEndpoint}/{tenantId}/oauth2/token");
            string clientAssertion = GetAadClientAssertion(clientId: clientId, audience: tokenUri.AbsoluteUri, certificate: certificate, expiration: TimeSpan.FromDays(1));
            //string clientAssertion = JsonEncryptionUtility.GetClientAssertionToken(clientId: clientId, audience: tokenUri.AbsoluteUri, certificate: certificate, expiration: TimeSpan.FromDays(1), sendX5C: true);
            var requestBody = new Dictionary<string, string>
            {
                { "resource", resource },
                { "client_id", clientId },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", clientAssertion },
                { "grant_type", "client_credentials" },
            };

            using (var request = new HttpRequestMessage(HttpMethod.Post, tokenUri))
            {
                //request.Content = new FormUrlEncodedContent(requestBody);
                request.Content = new StringContent(
                        "grant_type=client_credentials" +
                        $"&resource={Uri.EscapeUriString(resource)}" +
                        $"&client_id={clientId}" +
                        "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" +
                        $"&client_assertion={clientAssertion}",
                        Encoding.UTF8,
                        "application/x-www-form-urlencoded");
                Console.WriteLine(request.Content.ReadAsStringAsync().Result);

                HttpClientWithRetry client = new HttpClientWithRetry();
                var response = await client.SendAsync(request, CancellationToken.None);
                string content = await response.Content.ReadAsStringAsync();
                var responseJson = JObject.Parse(content);
                var accessToken = (string)responseJson["access_token"];
                var expiresOn = DateTime.Now.AddSeconds((long)responseJson["expires_in"]);
                var tokenType = (string)responseJson["token_type"];
                if (accessToken == null)
                {
                    throw new Exception($"Unable to get new access token from AAD response. AAD response: {content}");
                }

                return new CustomAuthResult { AccessToken = accessToken, ExpiresOn = expiresOn, TokenType = tokenType };
            }
        }

        /// <summary>
        /// Get the client assertion JSON Web Token.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="audience">The identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="certificate">The signing certificate.</param>
        /// <param name="expiration">The TTL for the token.</param>
        /// <param name="sendX5C">Setting this parameter to true will send the public certificate to Azure AD along with the token request, so that Azure AD can use it to validate the subject name based on a trusted issuer policy.</param>
        private static string GetClientAssertionToken(string clientId, string audience, X509Certificate2 certificate, TimeSpan? expiration, bool sendX5C)
        {
            var header = AadTokenProvider.GetJwtHeader(certificate, sendX5C);
            var payload = AadTokenProvider.GetJwtPayload(clientId, audience, expiration);
            var token = string.Concat(header, ".", payload);

            return string.Concat(token, ".", AadTokenProvider.GetJwtSignature(Encoding.UTF8.GetBytes(token), certificate));
        }

        private static string GetAadClientAssertion(string clientId, string audience, X509Certificate2 certificate, TimeSpan? expiration)
        {
            var header = new JObject
            {
                { "typ", "JWT" },
                { "alg", "RS256" },
                { "x5t", Convert.ToBase64String(certificate.GetCertHash()) },
                { "x5c", Convert.ToBase64String(certificate.GetRawCertData()) },
            }.ToString(Formatting.None);

            DateTime utcNow = DateTime.UtcNow;
            var claims = new JObject
            {
                { "sub", clientId },
                { "iss", clientId },
                { "jti", Guid.NewGuid().ToString() },
                { "exp", GetEpoch(utcNow + expiration.Value) },
                { "nbf", GetEpoch(utcNow) },
                { "aud", audience },
            }.ToString(Formatting.None);

            var encodedHeaderAndClaims = Base64UrlEncode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncode(Encoding.UTF8.GetBytes(claims));

            return encodedHeaderAndClaims + "." + GetJwtSignature(Encoding.UTF8.GetBytes(encodedHeaderAndClaims), certificate);
        }

        /// <summary>
        /// Gets the JSON Web Token header string.
        /// </summary>
        /// <param name="certificate">The signing certificate.</param>
        /// <param name="sendX5C">Setting this parameter to true will send the public certificate to Azure AD along with the token request, so that Azure AD can use it to validate the subject name based on a trusted issuer policy.</param>
        private static string GetJwtHeader(X509Certificate2 certificate, bool sendX5C)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "alg", "RS256" },
                { "typ", "JWT" },
            };

            if (sendX5C)
            {
                values["x5c"] = Convert.ToBase64String(certificate.GetRawCertData());
            }

            values["x5t"] = certificate.Thumbprint;

            return Base64UrlEncode(JsonConvert.SerializeObject(values));
        }

        /// <summary>
        /// Gets the JSON Web Token payload string.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="resource">The identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="expiration">The TTL for the token.</param>
        private static string GetJwtPayload(string clientId, string resource, TimeSpan? expiration)
        {
            var utcNow = DateTime.UtcNow;

            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", GetEpoch(utcNow).ToString().ToLowerInvariant() },
            };

            if (!string.IsNullOrEmpty(clientId))
            {
                values["iss"] = clientId;
                values["sub"] = clientId;
            }

            if (!string.IsNullOrEmpty(resource))
            {
                values["aud"] = resource;
            }

            if (expiration.HasValue)
            {
                values["exp"] = GetEpoch(utcNow + expiration.Value).ToString().ToLowerInvariant();
            }

            return Base64UrlEncode(JsonConvert.SerializeObject(values));
        }

        /// <summary>
        /// Gets the JSON Web Token signature over the <paramref name="data"/> using the provided credentials.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="certificate">The signing certificate.</param>
        private static string GetJwtSignature(byte[] data, X509Certificate2 certificate)
        {
#if NET45
            var asymmetricKey = new X509AsymmetricSecurityKey(certificate);

            using (var hash = asymmetricKey.GetHashAlgorithmForSignature(SecurityAlgorithms.RsaSha256Signature))
            {
                var formatter = asymmetricKey.GetSignatureFormatter(SecurityAlgorithms.RsaSha256Signature);
                formatter.SetHashAlgorithm("SHA256");

                return HttpUtility.Base64UrlEncode(formatter.CreateSignature(hash.ComputeHash(data)));
            }
#else
            //using (var privateKey = certificate.GetRSAPrivateKey())
            //{
            //    byte[] signedBytes = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            //    return Base64UrlEncode(signedBytes);
            //}

            var asymmetricKey = new X509AsymmetricSecurityKey(certificate);

            using (var hash = asymmetricKey.GetHashAlgorithmForSignature(SecurityAlgorithms.RsaSha256Signature))
            {
                var formatter = asymmetricKey.GetSignatureFormatter(SecurityAlgorithms.RsaSha256Signature);
                formatter.SetHashAlgorithm("SHA256");

                return Base64UrlEncode(formatter.CreateSignature(hash.ComputeHash(data)));
            }
#endif
        }

        private static string Base64UrlEncode(string input)
        {
            return Base64UrlEncode(Encoding.UTF8.GetBytes(input));
        }

        private static string Base64UrlEncode(byte[] input)
        {
            // Special "url-safe" base64 encode.
            return Convert.ToBase64String(input)
              .Replace('+', '-')
              .Replace('/', '_')
              .Replace("=", "");
        }

        private static long GetEpoch(DateTime dateTime)
        {
            long epochTicks = new DateTime(1970, 1, 1).Ticks;
            return ((dateTime.Ticks - epochTicks) / TimeSpan.TicksPerSecond);
        }
    }
}
