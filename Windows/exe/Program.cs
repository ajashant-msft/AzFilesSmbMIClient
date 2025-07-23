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
    using System;
    using System.Threading;
    using Microsoft.Azure.Files;

    class Program
    {
        static public void ShowUsage()
        {
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe set       <uri>");
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe refresh   <uri>");
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe set       <uri> <token>");
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe set       <uri> <token> <clientId>");
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe refresh   <uri> <clientId>");
            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")} Usage: AzFilesSmbMIClient.exe clear     <uri>");
        }

        public static class AzureFilesSmbAuthErrorCode
        {
            public const int S_OK = 0;
            public const int S_FALSE = 1;
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

            string verb = args[0].ToUpper();
            string uri = args[1];
            string token = args.Length < 3 ? "" : args[2];
            string clientId = args.Length < 4 ? "" : args[3];

            int hResult = AzureFilesSmbAuthErrorCode.S_FALSE;

            if (verb.Equals("SET"))
            {
                if (token.Length > 0)
                {
                    hResult = AzFilesSmbMI.SmbSetCredential(uri, token, clientId, out ulong expiryInSeconds);
                }
                else
                {
                    hResult = AzFilesSmbMI.SmbRefreshCredential(uri, clientId, out ulong expiryInSeconds);
                }
            }
            else if (verb.Equals("REFRESH"))
            {
                if(token.Length > 0)
                {
                    Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] Refresh only supported with managed identities.");
                    ShowUsage();
                    return -1;
                }

                ManualResetEvent resetEvent = new ManualResetEvent(false);

                Thread refreshThread = new Thread(() =>
                {
                    while (true)
                    {
                        hResult = AzFilesSmbMI.SmbRefreshCredential(uri, clientId, out ulong expiryInSeconds);

                        if(AzureFilesSmbAuthErrorCode.Failed(hResult))
                        {
                            Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] SmbRefreshCredential failed: {hResult}");
                            break;
                        }

                        var nextRefreshInSeconds = expiryInSeconds - 300; // next refresh when current token has 5mins of validity remaining.
                        Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] Next refresh in {nextRefreshInSeconds} seconds.");

                        Thread.Sleep(TimeSpan.FromSeconds(nextRefreshInSeconds));
                    }

                    Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] Child thread exiting.");
                    resetEvent.Set(); // Signal main thread
                });

                refreshThread.IsBackground = true; // Ensures it stops when the main thread exits
                refreshThread.Start();

                Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] Background auto-refresh running. App will exit ONLY if it encounters a failure.");
                resetEvent.WaitOne(); // Wait for signal from child thread

                Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] Main thread exiting.");
            }
            else if (verb.Equals("CLEAR"))
            {
                hResult = AzFilesSmbMI.SmbClearCredential(uri);
            }
            else
            {
                ShowUsage();
            }

            if(AzureFilesSmbAuthErrorCode.Failed(hResult))
            {
                Console.WriteLine($"{DateTime.Now.ToString("yyy-MM-dd HH:mm:ss:fff")}: [TID:{Thread.CurrentThread.ManagedThreadId}] {verb} creds for '{uri}' failed: {hResult}");
            }

            return hResult;
        }
    }
}