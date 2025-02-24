// AzureFilesSmbAuth.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include <string>
#include <winhttp.h>
#include <ntsecapi.h> // ntsec
#include <ctime>
#include <memory>
#include <vector>
#include <wincrypt.h>
#include <fstream>
#include <mutex>
#include <strsafe.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include "Logger.h"
#include "AzureFilesSmbAuth.h"

Logger s_logger;

#define LOG(level, format, ...) s_logger.log(__FUNCTIONW__, __LINE__, level, format, __VA_ARGS__);
#define LOGA(level, format, ...) s_logger.log(__FUNCTION__, __LINE__, level, format, __VA_ARGS__);

std::vector<unsigned char> from_base64(
    _In_ const std::string& str
    )
{
    DWORD outputSize = 0;
    BOOL bResult;

    bResult = ::CryptStringToBinaryA(str.c_str(), (DWORD)str.size(), CRYPT_STRING_BASE64, NULL, &outputSize, NULL, NULL);
    if (!bResult)
    {
        DWORD gle = ::GetLastError();
        HRESULT hrError = HRESULT_FROM_WIN32(gle);
        LOG(Logger::ERR, L"CryptStringToBinary failed to get size; GLE=%d, hr=0x%X", gle, hrError);
        throw hrError;
    }

    std::vector<unsigned char> decodedData(static_cast<size_t>(outputSize));

    bResult = ::CryptStringToBinaryA(str.c_str(), (DWORD)str.size(), CRYPT_STRING_BASE64, decodedData.data(), &outputSize, NULL, NULL);
    if (!bResult)
    {
        DWORD gle = ::GetLastError();
        HRESULT hrError = HRESULT_FROM_WIN32(gle);
        LOG(Logger::ERR, L"CryptStringToBinary failed to get binary; GLE=%d, hr=0x%X", gle, hrError);
        throw hrError;
    }

    return decodedData;
}

std::string GetValueFromJson(
    _In_ const std::string& json,
    _In_ const std::string& key)
{
    std::string searchKey = "\"" + key + "\":\"";
    std::size_t start = json.find(searchKey);
    if (start == std::string::npos) return ""; // Key not found
    start += searchKey.length();
    std::size_t end = json.find("\"", start);
    return std::move(json.substr(start, end - start));
}

std::wstring UTF8ToWide(const std::string& utf8Str)
{
    int wideSizeRequired = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
    if (wideSizeRequired == 0)
    {
        DWORD gle = GetLastError();
        HRESULT hrGle = HRESULT_FROM_WIN32(gle);
        LOG(Logger::ERR, L"MultiByteToWideChar failed to get size, with error GLE=%d, hr=0x%X", gle, hrGle);
        throw hrGle;
    }
    std::wstring wideStr(wideSizeRequired, 0);
    int wideSizeWritten = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wideStr[0], wideSizeRequired);
    if (wideSizeWritten == 0)
    {
        DWORD gle = GetLastError();
        HRESULT hrGle = HRESULT_FROM_WIN32(gle);
        LOG(Logger::ERR, L"MultiByteToWideChar failed to convert, with error GLE=%d, hr=0x%X", gle, hrGle);
        throw hrGle;
    }

    return std::move(wideStr);
}

HRESULT InsertKerberosTicket(
    _In_ const unsigned char* kerberosTicket,
    _In_ size_t               ticketLength
    )
{
    HANDLE lsaHandle;
    HRESULT hrError = S_OK;
    HRESULT hrLsa;
    NTSTATUS ntStatus;
    PVOID pResponse = nullptr;
    ULONG responseSize = 0;
    KERB_SUBMIT_TKT_REQUEST* pSubmitRequest = nullptr;

    try
    {
        ntStatus = ::LsaConnectUntrusted(&lsaHandle);
        if (ntStatus != 0)
        {
            hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaConnectUntrusted failed; ntstatus=%d, hr=0x%X", ntStatus, hrLsa);
            throw hrLsa;
        }
        // do the work

        // Lookup the Kerberos authentication package
        LSA_STRING packageName;
        ULONG authPackage;

        packageName.Buffer = const_cast<LPSTR>("Kerberos");
        packageName.Length = static_cast<USHORT>(strlen(packageName.Buffer));
        packageName.MaximumLength = packageName.Length + 1;

        ntStatus = LsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPackage);
        if (ntStatus != 0)
        {
            hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaLookupAuthenticationPackage failed; ntstatus=%d, hr=0x%X", ntStatus, hrLsa);
            throw hrLsa;
        }

        size_t submitRequestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticketLength;
        pSubmitRequest = (KERB_SUBMIT_TKT_REQUEST*)HeapAlloc(GetProcessHeap(), 0, submitRequestSize);
        if (!pSubmitRequest)
        {
            hrLsa = E_OUTOFMEMORY;
            LOG(Logger::ERR, L"Failed malloc KERB_SUBMIT_TKT_REQUEST. hr=0x%X", hrLsa);
            throw hrLsa;
        }

        LUID luidZero; luidZero.HighPart = 0; luidZero.LowPart = 0;
        pSubmitRequest->MessageType = KerbSubmitTicketMessage;
        pSubmitRequest->KerbCredSize = (ULONG)ticketLength;
        pSubmitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        pSubmitRequest->LogonId = luidZero;
        pSubmitRequest->Key.KeyType = 0;
        pSubmitRequest->Key.Length = 0;
        pSubmitRequest->Key.Offset = 0;
        memcpy(((BYTE*)pSubmitRequest) + pSubmitRequest->KerbCredOffset, kerberosTicket, ticketLength);

        // Submit the ticket
        DWORD dwRetriesLeft = 3;
        NTSTATUS ntProtocolStatus;
        do
        {
            ntStatus = ::LsaCallAuthenticationPackage(lsaHandle, authPackage, pSubmitRequest, (ULONG)submitRequestSize, &pResponse, &responseSize, &ntProtocolStatus);
            if ((ntStatus == 0) && (ntProtocolStatus == 0))
            {
                break;
            }

            if (pResponse != nullptr)
            {
                ::LsaFreeReturnBuffer(pResponse);
                pResponse = nullptr;
                responseSize = 0;
            }

            ::Sleep(500);

            dwRetriesLeft--;

            if (ntStatus != 0)
            {
                hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed; ntstatus=%d, hr=0x%X, retries left: %d", ntStatus, hrLsa, dwRetriesLeft);
            }

            if (ntProtocolStatus != 0)
            {
                hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntProtocolStatus));
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage succeeded but insertion failed; ntstatus=%d, hr=0x%X, retries left: %d", ntProtocolStatus, hrLsa, dwRetriesLeft);
            }

        } while (dwRetriesLeft > 0);

        if (ntStatus != 0)
        {
            hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed; ntstatus=%d, hr=0x%X", ntStatus, hrLsa);
            throw hrLsa;
        }

        if (ntProtocolStatus != 0)
        {
            hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntProtocolStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage succeeded but insertion failed; ntstatus=%d, hr=0x%X", __FILEW__, __LINE__, ntProtocolStatus, hrLsa);
            throw hrLsa;
        }
    }
    catch (const std::exception& e)
    {
        hrError = E_UNEXPECTED;
        LOGA(Logger::ERR, "Generic exception '%s' hr=0x%X.", e.what(), hrError);
    }
    catch (const HRESULT& CaughtHr)
    {
        hrError = CaughtHr;
    }

    if (pSubmitRequest)
    {
        HeapFree(GetProcessHeap(), 0, pSubmitRequest);
        pSubmitRequest = nullptr;
    }

    if (pResponse != nullptr)
    {
        HRESULT hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(::LsaFreeReturnBuffer(pResponse)));
        if (FAILED(hrLsa))
        {
            LOG(Logger::ERR, L"Failed LsaFreeReturnBuffer hr=0x%X.", hrLsa);
        }

        pResponse = nullptr;
        responseSize = 0;
    }

    if (lsaHandle)
    {
        HRESULT hrLsa = HRESULT_FROM_WIN32(LsaNtStatusToWinError(::LsaDeregisterLogonProcess(lsaHandle)));
        if (FAILED(hrLsa))
        {
            LOG(Logger::ERR, L"Failed LsaDeregisterLogonProcess hr=0x%X.", hrLsa);
        }

        hrError = FAILED(hrError) ? hrError : hrLsa;
    }

    return hrError;
}

HRESULT DisplayKerbTicket(
    _In_ PCWSTR pwszTargetName,
    _In_ bool   bPurge = false
    )
{
    HRESULT                       hrError = S_OK;
    HANDLE                        lsaHandle = NULL;
    KERB_RETRIEVE_TKT_REQUEST*    pTktCacheRequest = nullptr;
    KERB_RETRIEVE_TKT_RESPONSE*   pTktCacheResponse = nullptr;
    PVOID                         purgeResponse = nullptr;
    KERB_PURGE_TKT_CACHE_REQUEST* pTktPurgeRequest = nullptr;

    try
    {
        if (pwszTargetName == nullptr || pwszTargetName[0] == L'\0') throw E_INVALIDARG;

        hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(::LsaConnectUntrusted(&lsaHandle)));
        if (FAILED(hrError))
        {
            LOG(Logger::ERR, L"LsaConnectUntrusted failed hr=0x%X.", hrError);
            throw hrError;
        }

        LSA_STRING packageName;
        packageName.Buffer = const_cast<LPSTR>("Kerberos");
        packageName.Length = static_cast<USHORT>(strlen(packageName.Buffer));
        packageName.MaximumLength = packageName.Length + 1;

        ULONG authPackage;
        hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(::LsaLookupAuthenticationPackage(lsaHandle,
                                                                                            &packageName,
                                                                                            &authPackage)));
        if (FAILED(hrError)) 
        {
            LOG(Logger::ERR, L"LsaLookupAuthenticationPackage failed hr=0x%X.", hrError);
            throw hrError;
        }

        DWORD dwTargetNameSizeBytes = (DWORD)((wcslen(pwszTargetName)) * sizeof(wchar_t));
        KERB_RETRIEVE_TKT_REQUEST* pTktCacheRequest = (KERB_RETRIEVE_TKT_REQUEST*)HeapAlloc(GetProcessHeap(),
                                                                                            HEAP_ZERO_MEMORY,
                                                                                            dwTargetNameSizeBytes + sizeof(KERB_RETRIEVE_TKT_REQUEST));

        pTktCacheRequest->MessageType = KerbRetrieveEncodedTicketMessage; // Retrieve 
        pTktCacheRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
        pTktCacheRequest->LogonId.LowPart = 0;      // LUID, zero indicates
        pTktCacheRequest->LogonId.HighPart = 0;     //   current logon session

        LSA_UNICODE_STRING oTargetBuff = { 0 };
        oTargetBuff.Buffer = (LPWSTR)(pTktCacheRequest + 1);
        oTargetBuff.Length = (USHORT)(dwTargetNameSizeBytes);
        oTargetBuff.MaximumLength = (USHORT)(dwTargetNameSizeBytes);

        memcpy(oTargetBuff.Buffer, pwszTargetName, wcslen(pwszTargetName) * sizeof(wchar_t));
        pTktCacheRequest->TargetName = oTargetBuff;

        NTSTATUS                    ntSubStatus;
        DWORD                       dwResponseSize = 0;
        DWORD                       dwSubmitBufferLen = sizeof(KERB_RETRIEVE_TKT_REQUEST) + static_cast<DWORD>(dwTargetNameSizeBytes);

        hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(LsaCallAuthenticationPackage(lsaHandle,
                                                                                        authPackage,
                                                                                        static_cast<void*>(pTktCacheRequest),
                                                                                        dwSubmitBufferLen,
                                                                                        reinterpret_cast<void**>(&pTktCacheResponse),
                                                                                        &dwResponseSize,
                                                                                        &ntSubStatus)));

        if (FAILED(hrError)) 
        {
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed hr=0x%X.", hrError);
            throw hrError;
        }

        hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntSubStatus));
        if (FAILED(hrError)) 
        {
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage (ProtocolStatus) failed hr=0x%X.", hrError);
            throw hrError;
        }

        LOG(Logger::INFO, L"----------------------------------%ls----------------------------------", pwszTargetName);
        LOG(Logger::INFO, L"Client : %.*s @ %.*s",
            (DWORD)(pTktCacheResponse->Ticket.ClientName->Names->Length / sizeof(WCHAR)), pTktCacheResponse->Ticket.ClientName->Names->Buffer,
            (DWORD)(pTktCacheResponse->Ticket.DomainName.Length / sizeof(WCHAR)), pTktCacheResponse->Ticket.DomainName.Buffer);

        if (pTktCacheResponse->Ticket.TargetName)
        {
            LOG(Logger::INFO, L"Target : %.*s @ %.*s",
                (DWORD)(pTktCacheResponse->Ticket.TargetName->Names->Length / sizeof(WCHAR)), pTktCacheResponse->Ticket.TargetName->Names->Buffer,
                (DWORD)(pTktCacheResponse->Ticket.TargetDomainName.Length / sizeof(WCHAR)), pTktCacheResponse->Ticket.TargetDomainName.Buffer);
        }

        if (pTktCacheResponse->Ticket.ServiceName)
        {
            LOG(Logger::INFO, L"Service: %.*s",
                (DWORD)(pTktCacheResponse->Ticket.ServiceName->Names->Length / sizeof(WCHAR)), pTktCacheResponse->Ticket.ServiceName->Names->Buffer);
        }

        if (bPurge)
        {
            pTktPurgeRequest = (KERB_PURGE_TKT_CACHE_REQUEST*)HeapAlloc(GetProcessHeap(),
                                                                        HEAP_ZERO_MEMORY,
                                                                        dwTargetNameSizeBytes + sizeof(KERB_PURGE_TKT_CACHE_REQUEST));

            LSA_UNICODE_STRING oTargetBuff2 = { 0 };
            oTargetBuff2.Buffer = (LPWSTR)(pTktPurgeRequest + 1);
            oTargetBuff2.Length = (USHORT)(dwTargetNameSizeBytes);
            oTargetBuff2.MaximumLength = (USHORT)(dwTargetNameSizeBytes);

            memcpy(oTargetBuff2.Buffer, pwszTargetName, wcslen(pwszTargetName) * sizeof(wchar_t));
            pTktPurgeRequest->ServerName = oTargetBuff2;
            pTktPurgeRequest->LogonId.LowPart = 0;
            pTktPurgeRequest->LogonId.HighPart = 0;
            pTktPurgeRequest->MessageType = KerbPurgeTicketCacheMessage;

            DWORD dwSubmitBufferLen2 = sizeof(KERB_PURGE_TKT_CACHE_REQUEST) + static_cast<DWORD>(dwTargetNameSizeBytes);

            // Call the LSA function to purge the ticket
            ULONG responseSize;
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(LsaCallAuthenticationPackage(lsaHandle,
                                                                                            authPackage,
                                                                                            static_cast<void*>(pTktPurgeRequest),
                                                                                            dwSubmitBufferLen2,
                                                                                            static_cast<void**>(&purgeResponse),
                                                                                            &responseSize,
                                                                                            &ntSubStatus)));

            if (FAILED(hrError))
            {
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage hr=0x%X", hrError);
                throw hrError;
            }

            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntSubStatus));
            if (FAILED(hrError))
            {
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage (ProtocolStatus) hr=0x%X", hrError);
                throw hrError;
            }

            LOG(Logger::INFO, L"Purged '%ls'", pwszTargetName);
        }
    }
    catch (const std::exception& e)
    {
        hrError = E_UNEXPECTED;
        LOGA(Logger::ERR, "Generic exception '%s' hr=0x%X", e.what(), hrError);
    }
    catch (const HRESULT& CaughtHr)
    {
        hrError = CaughtHr;
    }

    // no throw beyond this point.

    HRESULT hrTemp = S_OK;

    // Cleanup
    if (pTktCacheRequest)
    {
        LOG(Logger::INFO, L"Clearing pTktCacheRequest");
        if (!HeapFree(GetProcessHeap(), 0, pTktCacheRequest))
        {
            hrTemp = ::GetLastError();
            LOG(Logger::ERR, L"HeapFree failed hr=0x%X", hrTemp);
        }
    }

    if (pTktCacheResponse)
    {
        LOG(Logger::INFO, L"Clearing pTktCacheResponse");
        hrTemp = HRESULT_FROM_WIN32(LsaNtStatusToWinError(LsaFreeReturnBuffer(pTktCacheResponse)));
        if (FAILED(hrTemp))
        {
            LOG(Logger::ERR, L"LsaFreeReturnBuffer(pTktCacheResponse) failed hr=0x%X", hrTemp);
        }
    }

    if (pTktPurgeRequest)
    {
        LOG(Logger::INFO, L"Clearing pTktPurgeRequest");
        if (!HeapFree(GetProcessHeap(), 0, pTktPurgeRequest))
        {
            hrTemp = ::GetLastError();
            LOG(Logger::ERR, L"HeapFree failed hr=0x%X", hrTemp);
        }
    }

    if (purgeResponse)
    {
        LOG(Logger::INFO, L"Clearing purgeResponse");
        hrTemp = HRESULT_FROM_WIN32(LsaNtStatusToWinError(LsaFreeReturnBuffer(purgeResponse)));
        if (FAILED(hrTemp))
        {
            LOG(Logger::ERR, L"LsaFreeReturnBuffer(purgeResponse) failed hr=0x%X", hrTemp);
        }
    }

    if (lsaHandle != NULL)
    {
        hrTemp = HRESULT_FROM_WIN32(LsaNtStatusToWinError(::LsaDeregisterLogonProcess(lsaHandle)));
        if (FAILED(hrTemp))
        {
            LOG(Logger::ERR, L"LsaDeregisterLogonProcess failed hr=0x%X", hrTemp);
        }
    }

    return hrError;
}

std::unique_ptr<wchar_t[]> GetAllResponseHeaders(
    _In_ HINTERNET hRequest
    )
{
    std::unique_ptr<wchar_t[]> spszHeader;

    {
        DWORD bufferSizeBytes = 0;

        // When WINHTTP_NO_OUTPUT_BUFFER is passed, WinHttpQueryHeaders API
        // is supposed to fail with ERROR_INSUFFICIENT_BUFFER error code
        if (!WinHttpQueryHeaders(hRequest,
                                 WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 WINHTTP_NO_OUTPUT_BUFFER,
                                 &bufferSizeBytes,
                                 WINHTTP_NO_HEADER_INDEX))
        {
            DWORD dwError = GetLastError();

            if (dwError == ERROR_INSUFFICIENT_BUFFER)
            {
                // in case of that bufferSizeBytes is an odd number
                bufferSizeBytes /= sizeof(wchar_t);
                spszHeader.reset(new wchar_t[bufferSizeBytes]);
                bufferSizeBytes *= sizeof(wchar_t);

                if (!WinHttpQueryHeaders(hRequest,
                                         WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                         WINHTTP_HEADER_NAME_BY_INDEX,
                                         spszHeader.get(),
                                         &bufferSizeBytes,
                                         WINHTTP_NO_HEADER_INDEX))
                {
                    dwError = GetLastError();
                }
            }
            else
            {
                HRESULT hr = HRESULT_FROM_WIN32(dwError);
                LOG(Logger::ERR, L"WinHttpQueryHeaders failed with gle=%d, hr=0x%X", dwError, hr);
            }
        }
    }

    return spszHeader;
}

struct ErrorMapEntry
{
    DWORD   sc;
    HRESULT hr;
};

HRESULT MapError(DWORD sc, const ErrorMapEntry* mapv, int mapc, HRESULT defaultHr)
{
    for (int i = 0; i < mapc; i++)
    {
        if (mapv[i].sc == sc)
        {
            return mapv[i].hr;
        }
    }

    return defaultHr;
}

HRESULT HTTPStatusToHresult(DWORD sc)
{
    static const ErrorMapEntry s_Convert[] =
    {
        { HTTP_STATUS_AMBIGUOUS,            HTTP_E_STATUS_AMBIGUOUS            },
        { HTTP_STATUS_MOVED,                HTTP_E_STATUS_MOVED                },
        { HTTP_STATUS_REDIRECT,             HTTP_E_STATUS_REDIRECT             },
        { HTTP_STATUS_REDIRECT_METHOD,      HTTP_E_STATUS_REDIRECT_METHOD      },
        { HTTP_STATUS_NOT_MODIFIED,         HTTP_E_STATUS_NOT_MODIFIED         },
        { HTTP_STATUS_USE_PROXY,            HTTP_E_STATUS_USE_PROXY            },
        { HTTP_STATUS_REDIRECT_KEEP_VERB,   HTTP_E_STATUS_REDIRECT_KEEP_VERB   },
        { HTTP_STATUS_BAD_REQUEST,          HTTP_E_STATUS_BAD_REQUEST          },
        { HTTP_STATUS_DENIED,               HTTP_E_STATUS_DENIED               },
        { HTTP_STATUS_PAYMENT_REQ,          HTTP_E_STATUS_PAYMENT_REQ          },
        { HTTP_STATUS_FORBIDDEN,            HTTP_E_STATUS_FORBIDDEN            },
        { HTTP_STATUS_NOT_FOUND,            HTTP_E_STATUS_NOT_FOUND            },
        { HTTP_STATUS_BAD_METHOD,           HTTP_E_STATUS_BAD_METHOD           },
        { HTTP_STATUS_NONE_ACCEPTABLE,      HTTP_E_STATUS_NONE_ACCEPTABLE      },
        { HTTP_STATUS_PROXY_AUTH_REQ,       HTTP_E_STATUS_PROXY_AUTH_REQ       },
        { HTTP_STATUS_REQUEST_TIMEOUT,      HTTP_E_STATUS_REQUEST_TIMEOUT      },
        { HTTP_STATUS_CONFLICT,             HTTP_E_STATUS_CONFLICT             },
        { HTTP_STATUS_GONE,                 HTTP_E_STATUS_GONE                 },
        { HTTP_STATUS_LENGTH_REQUIRED,      HTTP_E_STATUS_LENGTH_REQUIRED      },
        { HTTP_STATUS_PRECOND_FAILED,       HTTP_E_STATUS_PRECOND_FAILED       },
        { HTTP_STATUS_REQUEST_TOO_LARGE,    HTTP_E_STATUS_REQUEST_TOO_LARGE    },
        { HTTP_STATUS_URI_TOO_LONG,         HTTP_E_STATUS_URI_TOO_LONG         },
        { HTTP_STATUS_UNSUPPORTED_MEDIA,    HTTP_E_STATUS_UNSUPPORTED_MEDIA    },
        { HTTP_STATUS_SERVER_ERROR,         HTTP_E_STATUS_SERVER_ERROR         },
        { HTTP_STATUS_NOT_SUPPORTED,        HTTP_E_STATUS_NOT_SUPPORTED        },
        { HTTP_STATUS_BAD_GATEWAY,          HTTP_E_STATUS_BAD_GATEWAY          },
        { HTTP_STATUS_SERVICE_UNAVAIL,      HTTP_E_STATUS_SERVICE_UNAVAIL      },
        { HTTP_STATUS_GATEWAY_TIMEOUT,      HTTP_E_STATUS_GATEWAY_TIMEOUT      },
        { HTTP_STATUS_VERSION_NOT_SUP,      HTTP_E_STATUS_VERSION_NOT_SUP      },
    };

    return MapError(sc, s_Convert, ARRAYSIZE(s_Convert), HTTP_E_STATUS_BAD_REQUEST /*defaultHr*/);
}

HRESULT DoHttpVerb(
    _In_      const std::wstring& verb,
    _In_      const std::wstring& requestUrl,
    _In_opt_  const std::wstring& oauthToken,
    _Out_     std::string& winhttpResponse)
{
    LOG(Logger::VERBOSE, L"BEGIN");

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    HRESULT hrError = S_OK;

    winhttpResponse.clear();

    try
    {
        // Parse the URL components
        URL_COMPONENTS urlComp;
        memset(&urlComp, 0, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        wchar_t hostName[256] = {};
        wchar_t urlPath[256] = {};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);

        BOOL bResult;
        bResult = WinHttpCrackUrl(requestUrl.c_str(), 0, 0, &urlComp);

        if (!bResult)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpAddRequestHeaders, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
            throw hrError;
        }

        bool bUseHttps = true;
        bool bIsIMDSQuery = false;
        winhttpResponse.clear();

        LOG(Logger::INFO, L"%ls %ls", verb.c_str(), requestUrl.c_str());

        if (requestUrl.substr(0, 8) == L"https://")
        {
            bUseHttps = true;
            if (oauthToken.empty())
            {
                LOG(Logger::ERR, L"E_INVALIDARG - OAuth token is needed for 'https://' queries", requestUrl.c_str());
                throw E_INVALIDARG;
            }
        }
        else if (requestUrl.substr(0, 7) == L"http://")
        {
            bUseHttps = false;
            if (!oauthToken.empty())
            {
                LOG(Logger::ERR, L"E_INVALIDARG - OAuth token is NOT needed for 'http://' queries", requestUrl.c_str());
                throw E_INVALIDARG;
            }

            if (requestUrl.substr(0, 22) == L"http://169.254.169.254")
            {
                bIsIMDSQuery = true;
            }
        }
        else
        {
            LOG(Logger::ERR, L"File URI '%ls' is not prefixed with 'http://' or 'https://'", requestUrl.c_str());
            throw E_INVALIDARG;
        }

        // Open a WinHTTP session
        hSession = WinHttpOpen( L"AzureFilesSmbMIAuth",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS,
                                0);

        if (!hSession)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpOpen, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
            throw hrError;
        }

        // Specify the target server
        hConnect = WinHttpConnect(  hSession,
                                    urlComp.lpszHostName,
                                    bUseHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
                                    0);
        if (!hConnect)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpConnect, server %ls, hr=0x%X",  requestUrl.c_str(), hrError);
            throw hrError;
        }

        // Create an HTTP request handle
        hRequest = WinHttpOpenRequest(  hConnect,
                                        verb.c_str(),
                                        urlComp.lpszUrlPath,
                                        bUseHttps ? L"HTTP/2" : NULL,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        bUseHttps ? WINHTTP_FLAG_SECURE : 0);

        if (!hRequest)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpOpenRequest(%ls), server %ls, hr=0x%X", verb.c_str(), requestUrl.c_str(), hrError);
            throw hrError;
        }

        // construct headers
        time_t rawtime;
        struct tm timeinfo;
        char buffer[128];

        // Get the UTC/GMT time
        time(&rawtime);
        gmtime_s(&timeinfo, &rawtime);
        strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &timeinfo);
        std::wstring xMsDateHeader = L"x-ms-date: " + std::wstring(buffer, buffer + strlen(buffer));

        std::wstring wstrToken = L"Authorization: Bearer " + oauthToken;
        std::wstring wstrApiVersion = L"x-ms-version: 2024-05-04"; // YYYY-DD-MM

        if (bIsIMDSQuery)
        {
             std::wstring headers = L"Metadata: true\r\n";

            // Send the request
            bResult = WinHttpSendRequest(hRequest,
                                         headers.c_str(), (DWORD)headers.size(),
                                         WINHTTP_NO_REQUEST_DATA,
                                         0,
                                         0,
                                         0);
        }
        else
        {
            bResult = ::WinHttpAddRequestHeaders(hRequest,
                                                 wstrApiVersion.c_str(),
                                                 (DWORD)-1L,
                                                 WINHTTP_ADDREQ_FLAG_ADD);

            if (!bResult)
            {
                hrError = HRESULT_FROM_WIN32(::GetLastError());
                LOG(Logger::ERR, L"WinHttpAddRequestHeaders, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
                throw hrError;
            }

            bResult = ::WinHttpAddRequestHeaders(hRequest,
                                                 xMsDateHeader.c_str(),
                                                 (DWORD)-1L,
                                                 WINHTTP_ADDREQ_FLAG_ADD);
            if (!bResult)
            {
                hrError = HRESULT_FROM_WIN32(::GetLastError());
                LOG(Logger::ERR, L"WinHttpAddRequestHeaders, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
                throw hrError;
            }

            bResult = ::WinHttpAddRequestHeaders(hRequest,
                                                 wstrToken.c_str(),
                                                 (DWORD)-1L,
                                                 WINHTTP_ADDREQ_FLAG_ADD);
            if (!bResult)
            {
                hrError = HRESULT_FROM_WIN32(::GetLastError());
                LOG(Logger::ERR, L"WinHttpAddRequestHeaders, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
                throw hrError;
            }

            // Send the request
            bResult = WinHttpSendRequest(hRequest,
                                         WINHTTP_NO_ADDITIONAL_HEADERS, (DWORD)-1L,
                                         WINHTTP_NO_REQUEST_DATA,
                                         0,
                                         0,
                                         0);
        }

        if (!bResult) {
            DWORD gle = GetLastError();
            hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"WinHttpSendRequest, server %ls, gle=%d, hr=0x%X", requestUrl.c_str(), gle, hrError);
            throw hrError;
        }

        // Receive the Response
        bResult = WinHttpReceiveResponse(hRequest,
                                         NULL);
        if (!bResult)
        {
            DWORD gle = GetLastError();
            hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"WinhttpReceiveResponse, server %ls, gle=%d, hr=0x%X", requestUrl.c_str(), gle, hrError);
            throw hrError;
        }

        DWORD dwStatusCode = 0;
        DWORD bufferSize = sizeof(dwStatusCode);

        bResult = WinHttpQueryHeaders(  hRequest,
                                        WINHTTP_QUERY_STATUS_CODE |
                                        WINHTTP_QUERY_FLAG_NUMBER,
                                        nullptr,
                                        &dwStatusCode,
                                        &bufferSize,
                                        WINHTTP_NO_HEADER_INDEX);

        if (!bResult)
        {
            DWORD gle = GetLastError();
            hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"WinHttpQueryHeaders, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
            throw hrError;
        }

        LOG(Logger::INFO, L"http status=%d", dwStatusCode);

        // Read the Response data (even in error cases).
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        LPSTR pszOutBuffer = NULL;

        do 
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest,
                                           &dwSize))
            {
                DWORD gle = GetLastError();
                hrError = HRESULT_FROM_WIN32(gle);
                LOG(Logger::ERR, L"WinHttpQueryDataAvailable, server %ls, gle=%d, hr=0x%X", requestUrl.c_str(), gle, hrError);
                throw hrError;
            }

            if (dwSize == 0) break;

            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                hrError = E_OUTOFMEMORY;
                LOG(Logger::ERR, L"Failed to WinHttpQueryDataAvailable, server %ls, hr=0x%X", requestUrl.c_str(), hrError);
                throw hrError;
            }

            ZeroMemory(pszOutBuffer, dwSize + 1);

            if (!WinHttpReadData(hRequest,
                                 (LPVOID)pszOutBuffer,
                                 dwSize,
                                 &dwDownloaded))
            {
                DWORD gle = GetLastError();
                hrError = HRESULT_FROM_WIN32(gle);
                LOG(Logger::ERR, L"WinHttpReadData, server %ls, gle=%d, hr=0x%X", requestUrl.c_str(), gle, hrError);
                throw hrError;
            }

            winhttpResponse.append(pszOutBuffer, dwDownloaded);

            delete[] pszOutBuffer;

        } while (dwSize > 0);

        if ((dwStatusCode < 200) || (dwStatusCode > 299))
        {
            std::unique_ptr<wchar_t[]> headers = GetAllResponseHeaders(hRequest);

            hrError = HTTPStatusToHresult(dwStatusCode);
            LOG(Logger::ERR, L"Request FAILED.  server %ls;  httpStatus=%d;  hr=0x%X;  Response HEADERS: %ls", requestUrl.c_str(), dwStatusCode, hrError, headers.get());
            LOGA(Logger::ERR, "Response received: %s", winhttpResponse.c_str());
            throw hrError;
        }

        LOG(Logger::INFO, L"SUCCESS");
    }
    catch (const std::exception& e)
    {
        LOGA(Logger::ERR, "Generic Exception '%s'", e.what());
        hrError = E_FAIL;
    }
    catch (const HRESULT& CaughtHr)
    {
        hrError = CaughtHr;
    }

    // Clean up resources
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    LOG(Logger::VERBOSE, L"END");

    return hrError;
}

std::string getCurrentTimeISO8601() {
    // Get the current time in system_clock (UTC)
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::tm tm_time{};
    gmtime_s(&tm_time, &now);

    // Format the time into an ISO 8601 string
    std::ostringstream oss;
    oss << std::put_time(&tm_time, "%Y-%m-%dT%H:%M:%S");

    return oss.str();
}

DWORD elapsedSecondsFromNow(
    _In_ const std::string& timestamp
    )
{
    // Parse the timestamp into struct tm
    std::tm tm_time = {};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tm_time, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail())
    {
        throw std::runtime_error("Failed to parse timestamp.");
    }

    std::time_t local_time = std::mktime(&tm_time);

    long seconds;
    auto err = _get_timezone(&seconds);

    // Convert to UTC by subtracting the timezone offset
    std::time_t time_stamp_t = local_time - seconds;  // Adjust for UTC

    // Get current UTC time
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    // Compute difference in seconds
    return (DWORD)std::difftime(time_stamp_t, now);
}

HRESULT SmbSetCredentialInternal(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_  PCWSTR pwszOauthToken,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
    )
{
    // Initialize logger first
    s_logger.Initialize();

    LOG(Logger::VERBOSE, L"BEGIN");

    HRESULT hrError = S_OK;
    if (pdwCredentialExpiresInSeconds)
    {
        *pdwCredentialExpiresInSeconds = 0;
    }

    try
    {
        std::wstring wstrAccountFileUri = pwszFileEndpointUri;
        std::wstring wstrAccessToken = pwszOauthToken;

        BOOL bGetTokenFromImds = wstrAccessToken.empty();
        LOG(Logger::INFO, L"Authenticating access to '%ls' %ls", wstrAccountFileUri.c_str(), bGetTokenFromImds ? L"by fetching OAuth token from IMDS" : L"using provided OAuth token");

        if (pwszFileEndpointUri == nullptr || pwszFileEndpointUri[0] == L'\0') throw E_INVALIDARG;
        if (pdwCredentialExpiresInSeconds == nullptr) throw E_INVALIDARG;
        if (wstrAccountFileUri[wstrAccountFileUri.length() - 1] != L'/') throw E_INVALIDARG;

        if (wstrAccountFileUri.substr(0, 8) != L"https://")
        {
            LOG(Logger::ERR, L"File URI '%ls' is not prefixed with 'https://'", wstrAccountFileUri.c_str());
            throw E_INVALIDARG;
        }

        std::string strHttpResponse;

        if (bGetTokenFromImds)
        {
            hrError = DoHttpVerb(L"GET",
                                 L"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
                                 L"",
                                 strHttpResponse);
            if (FAILED(hrError))
            {
                LOG(Logger::ERR, L"GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/ failed with error hr=0x%X", hrError);
                throw hrError;
            }

            std::string  access_tokenstr = GetValueFromJson(strHttpResponse, "access_token");
            wstrAccessToken = UTF8ToWide(access_tokenstr);
            strHttpResponse.clear();
        }

        hrError = DoHttpVerb(L"POST",
                             wstrAccountFileUri + L"?restype=service&comp=kerbticket",
                             wstrAccessToken,
                             strHttpResponse);
        if (FAILED(hrError))
        {
            throw hrError;
        }

        std::string sessionKey = GetValueFromJson(strHttpResponse, "sessionKey");
        std::string expiration = GetValueFromJson(strHttpResponse, "expirationTime");
        std::string kerbTicket = GetValueFromJson(strHttpResponse, "kerberosServiceTicket");

        expiration = expiration.erase(expiration.size() - 5, 5); // remove trailing ".000Z"
        std::vector<unsigned char> decodedTicket = from_base64(kerbTicket);

        LOGA(Logger::INFO, "SessionKey: '%s'", sessionKey.c_str());
        LOGA(Logger::INFO, "ExpirationTime: '%s'", expiration.c_str());

        DWORD dwExpiresInSeconds = elapsedSecondsFromNow(expiration);
        LOGA(Logger::INFO, "Expires in: '%d' seconds from now (%s)", dwExpiresInSeconds, getCurrentTimeISO8601().c_str());
        LOG(Logger::INFO, L"Encoded kerberosServiceTicket length(bytes): '%llu'", kerbTicket.size());
        LOG(Logger::INFO, L"Decoded kerberosServiceTicket length(bytes): '%llu'", decodedTicket.size());

        hrError = InsertKerberosTicket(decodedTicket.data(), decodedTicket.size());
        if (FAILED(hrError))
        {
            throw hrError;
        }

        *pdwCredentialExpiresInSeconds = dwExpiresInSeconds;

        LOG(Logger::INFO, L"SUCCESS");
    }
    catch (const std::exception& e)
    {
        hrError = E_FAIL;
        LOGA(Logger::ERR, "Generic exception '%s' hr=0x%X", e.what(), hrError);
    }
    catch (const HRESULT& CaughtHr)
    {
        hrError = CaughtHr;
        LOG(Logger::ERR, L"HRESULT exception hr=0x%X", hrError);
    }

    LOG(Logger::VERBOSE, L"END", hrError);
    return hrError;
}

HRESULT SmbShowOrClearCredentialInternal(
    _In_  bool   bClear,
    _In_  PCWSTR pwszFileEndpointUri
    )
{
    // Initialize logger first
    s_logger.Initialize();

    HRESULT hrError = S_OK;

    try
    {
        if (pwszFileEndpointUri == nullptr || pwszFileEndpointUri[0] == L'\0') throw E_INVALIDARG;
        if (pwszFileEndpointUri[wcslen(pwszFileEndpointUri) - 1] != L'/') throw E_INVALIDARG;

        std::wstring wstrFileUri = pwszFileEndpointUri;
        wstrFileUri.pop_back(); // removing trailing '/'
        wstrFileUri = wstrFileUri.substr(8);   // remove https://
        wstrFileUri = L"cifs/" + wstrFileUri;  // append cifs/

        hrError = DisplayKerbTicket(wstrFileUri.c_str(), bClear /*bPurge*/);
        if (FAILED(hrError))
        {
            throw hrError;
        }
    }
    catch (const std::exception& e)
    {
        hrError = E_FAIL;
        LOGA(Logger::ERR, "Generic exception '%s' hr=0x%X", e.what(), hrError);
    }
    catch (const HRESULT& CaughtHr)
    {
        hrError = CaughtHr;
        LOG(Logger::ERR, L"HRESULT exception hr=0x%X", hrError);
    }

    return hrError;
}
