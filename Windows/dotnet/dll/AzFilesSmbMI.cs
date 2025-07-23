// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AzFilesSmbMI.cs" company="Microsoft Corporation.">
//   All rights reserved.
// </copyright>
// <summary>
//   AzFilesSmbMI is a library that provides methods to manage Azure Files SMB authentication using Managed Identities or OAuth tokens.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace Microsoft.Azure.Files
{
    using System.Runtime.InteropServices;

    public class AzFilesSmbMI
    {
        [DllImport("AzFilesSmbMI.DLL", SetLastError = false,
                CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int SmbSetCredential(
                        string FileEndpointUri,
                        string OAuthToken,
                        string clientId,
                        [MarshalAs(UnmanagedType.U8)] out ulong ExpiryInSeconds);

        [DllImport("AzFilesSmbMI.DLL", SetLastError = false,
            CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int SmbRefreshCredential(
                    string FileEndpointUri,
                    string clientId,
                    [MarshalAs(UnmanagedType.U8)] out ulong ExpiryInSeconds);

        [DllImport("AzFilesSmbMI.DLL", SetLastError = false,
            CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        public static extern int SmbClearCredential(
                    string FileEndpointUri);
    }
}