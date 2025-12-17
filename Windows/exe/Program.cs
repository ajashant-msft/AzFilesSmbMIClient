// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Program.cs" company="Microsoft Corporation.">
//   All rights reserved.
// </copyright>
// <summary>
//   AzFilesSmbMIClient is a command line utility to manage Azure Files SMB authentication using Managed Identities or OAuth tokens.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace AzFilesSmbMIClient
{
    using Microsoft.Azure.Files;
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading;

    class Program
    {
        static public void ShowUsage()
        {
            TraceMessage($"Usage: AzFilesSmbMIClient.exe <command> [options]");
            TraceMessage($"");
            TraceMessage($"Commands:");
            TraceMessage($"  set     - Set Azure Files SMB credentials");
            TraceMessage($"  refresh - Refresh Azure Files SMB credentials");
            TraceMessage($"  clear   - Clear Azure Files SMB credentials");
            TraceMessage($"");
            TraceMessage($"Options:");
            TraceMessage($"  --uri <uri>               - (Required) Azure Files endpoint URI");
            TraceMessage($"  --token <token>           - OAuth token (for 'set' command)");
            TraceMessage($"  --clientId <id>           - User managed identity client ID");
            TraceMessage($"  --expiry <seconds>        - Time in seconds for refresh operation (default: 86400)");
            TraceMessage($"");
            TraceMessage($"Examples:");
            TraceMessage($"  AzFilesSmbMIClient.exe set --uri https://myaccount.file.core.windows.net/");
            TraceMessage($"  AzFilesSmbMIClient.exe set --uri https://myaccount.file.core.windows.net/ --token mytoken");
            TraceMessage($"  AzFilesSmbMIClient.exe refresh --uri https://myaccount.file.core.windows.net/ --clientId myclient --expiry 3600");
            TraceMessage($"  AzFilesSmbMIClient.exe clear --uri https://myaccount.file.core.windows.net/");
            TraceMessage($"");
        }

        public static class AzFilesSmbMIClientErrorCode
        {
            public const int S_OK = 0;
            public const int S_FALSE = 1;
            public const int E_NOTFOUND = -2147024894;   // 0x80070002
            public const int E_INVALIDARG = -2147024809; // 0x80070057
            public static bool Succeeded(int hr)
            {
                return (hr >= S_OK);
            }
            public static bool Failed(int hr)
            {
                return (hr < S_OK);
            }
        }

        static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                ShowUsage();
                return -1;
            }

            // Check if using new named parameter format or legacy positional format
            bool usingNamedParams = args.Length > 1 && args[1].StartsWith("--");

            Dictionary<string, string> parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string verb = args[0].ToUpper();

            if (usingNamedParams)
            {
                // Parse named parameters
                parameters = ParseNamedParameters(args);
            }
            else
            {
                ShowUsage();
                return -1;
            }

            // Validate required parameters
            if (!parameters.ContainsKey("uri") || string.IsNullOrWhiteSpace(parameters["uri"]))
            {
                TraceMessage("Error: URI parameter is required");
                ShowUsage();
                return AzFilesSmbMIClientErrorCode.E_INVALIDARG;
            }

            // Extract parameters with defaults
            string uri = parameters["uri"];
            string token = parameters.ContainsKey("token") ? parameters["token"] : "";
            string clientId = parameters.ContainsKey("clientId") ? parameters["clientId"] : "";
            string refreshExpiryInSeconds = parameters.ContainsKey("expiry") ? parameters["expiry"] : "86400";

            int hResult = AzFilesSmbMIClientErrorCode.S_FALSE;

            if (verb.Equals("SET"))
            {
                var loggingMessage = new StringBuilder();
                
                if (token.Length == 0)
                {
                    loggingMessage.Append("Token will be obtained via IMDS endpoint. ");
                }
                else
                {
                    loggingMessage.Append($"Using OAuth Token: '{token}' ");
                }

                if (clientId.Length > 0)
                {
                    loggingMessage.Append($"Using User Identity ClientId: '{clientId}'");
                }

                TraceMessage(loggingMessage.ToString());

                hResult = AzFilesSmbMI.SmbSetCredential(uri, token, clientId, out ulong expiryInSeconds);

                if (AzFilesSmbMIClientErrorCode.Succeeded(hResult))
                {
                    TraceMessage($"{verb} SUCCEEDED for {uri}.  Access is valid for {expiryInSeconds} seconds from now.");
                }
            }
            else if (verb.Equals("REFRESH"))
            {
                if (token.Length > 0)
                {
                    TraceMessage($"Refresh only supported with machine identities.");
                    ShowUsage();
                    return -1;
                }

                if (!int.TryParse(refreshExpiryInSeconds, out int expireTimeSeconds))
                {
                    TraceMessage($"Please provide a valid duration for how long to keep refreshing.");
                    ShowUsage();
                    return AzFilesSmbMIClientErrorCode.E_INVALIDARG;
                }

                hResult = AzFilesSmbMI.SmbRefreshCredential(uri, clientId);

                if (AzFilesSmbMIClientErrorCode.Succeeded(hResult))
                {
                    TraceMessage($"Auto refresh is running in the background; Will end only after {expireTimeSeconds} seconds or if it encounters an error.");
                    Thread.Sleep(TimeSpan.FromSeconds(expireTimeSeconds));

                    TraceMessage($"Auto refresh will end now.");
                }

                TraceMessage($"Main thread exiting.");
            }
            else if (verb.Equals("CLEAR"))
            {
                hResult = AzFilesSmbMI.SmbClearCredential(uri);
            }
            else
            {
                ShowUsage();
            }

            if (AzFilesSmbMIClientErrorCode.Failed(hResult))
            {
                TraceMessage($"{verb} creds for '{uri}' failed: {hResult}");
            }

            return hResult;
        }

        /// <summary>
        /// Parses named command-line parameters in the format --name value
        /// </summary>
        private static Dictionary<string, string> ParseNamedParameters(string[] args)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Skip the first argument (command verb)
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    string paramName = args[i].Substring(2).ToLowerInvariant();

                    // Check if there's a value available
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    {
                        parameters[paramName] = args[i + 1];
                        i++; // Skip the value in the next iteration
                    }
                    else
                    {
                        // Parameter without value, treat as flag
                        parameters[paramName] = "true";
                    }
                }
            }

            return parameters;
        }

        private static void TraceMessage(string message)
        {
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] {message}");
        }
    }
}