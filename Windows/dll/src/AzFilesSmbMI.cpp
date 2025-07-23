/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    AzFilesSmbMI.cpp: Defines the exported functions for the DLL.

Abstract:

    C++ class that implements methods that allow clients to
    authenticate with AzureFiles for accessing shares over SMB.

--*/

#include "pch.h"
#include "framework.h"
#include <string>
#include <winhttp.h>
#include <ntsecapi.h>
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
#include <unordered_map>
#include "Logger.h"
#include "AzFilesSmbMI.h"

// Forward declarations
std::vector<unsigned char> FromBase64(_In_ const std::string& str);
std::string GetValueFromJson(_In_ const std::string& json, _In_ const std::string& key);
std::wstring UTF8ToWide(_In_ const std::string& utf8Str);
HRESULT InsertKerberosTicket(_In_ const unsigned char* kerberosTicket, _In_ size_t ticketLength);
HRESULT DisplayKerbTicket(_In_ PCWSTR pwszTargetName, _In_ bool bPurge);
std::unique_ptr<wchar_t[]> GetAllResponseHeaders(_In_ HINTERNET hRequest);
HRESULT HTTPStatusToHresult(_In_ DWORD sc);
HRESULT DoHttpVerb( _In_ const std::wstring& verb, _In_ const std::wstring& requestUrl, _In_opt_ const std::wstring& oauthToken, _Out_ std::string& winhttpResponse);
std::string GetCurrentTimeISO8601();
DWORD ElapsedSecondsFromNow(_In_ const std::string& timestamp);

// Global logger instance
Logger s_logger;

struct HandleDeleter {
    void operator()(HANDLE handle) const noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

// Alias for smart HANDLE using unique_ptr
using UniqueHandle = std::unique_ptr<std::remove_pointer<HANDLE>::type, HandleDeleter>;

struct RefreshContext
{
    PTP_TIMER    timer;
    UniqueHandle shEvent;
    HRESULT      hrRefresh;
    std::wstring wstrFileEndpointUri;
    std::wstring wstrClientID;

    RefreshContext(_In_ PCWSTR pwszFileEndpointUri, _In_opt_ PCWSTR pwszClientID = nullptr)
    {
        timer = nullptr;
        shEvent = nullptr;
        hrRefresh = S_FALSE;
        wstrFileEndpointUri = pwszFileEndpointUri;
        if (pwszClientID && pwszClientID[0] != L'\0')
        {
            wstrClientID = pwszClientID;
        }
    }
};

// Global tracking of refresh contexts
std::unordered_map<std::wstring, std::shared_ptr<RefreshContext>> s_timerMap;
std::mutex timerMapMutex;

// Simplified logging macros
#define LOG(level, format, ...) s_logger.log(__FUNCTIONW__, __LINE__, level, format, ## __VA_ARGS__)
#define LOGA(level, format, ...) s_logger.log(__FUNCTION__, __LINE__, level, format, ## __VA_ARGS__)

// Base64 decoding implementation with improved error handling and input validation
std::vector<unsigned char> FromBase64(_In_ const std::string& str)
{
    // Early check for empty input
    if (str.empty()) {
        LOG(Logger::WARN, L"Empty base64 string provided to FromBase64");
        return std::vector<unsigned char>();
    }

    try {
        DWORD outputSize = 0;
        BOOL bResult;

        // Validate that the input resembles Base64 (basic check)
        // Check if string length is a multiple of 4 plus optional padding
        if (str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != std::string::npos) {
            LOG(Logger::ERR, L"Input contains characters invalid for Base64 encoding");
            throw E_INVALIDARG;
        }

        // First call to get required buffer size
        bResult = ::CryptStringToBinaryA(
            str.c_str(),
            static_cast<DWORD>(str.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &outputSize,
            nullptr,
            nullptr
        );

        if (!bResult)
        {
            DWORD gle = ::GetLastError();
            HRESULT hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"Base64 decode failed during size calculation: error=%d, hr=0x%X", gle, hrError);
            throw hrError;
        }

        // Check for suspiciously large output size that might indicate an attack
        constexpr DWORD MAX_REASONABLE_SIZE = 10 * 1024 * 1024; // 10MB
        if (outputSize > MAX_REASONABLE_SIZE) {
            LOG(Logger::ERR, L"Base64 decode would produce unexpectedly large output (%u bytes)", outputSize);
            throw E_OUTOFMEMORY;
        }

        // Pre-allocate vector with required size
        std::vector<unsigned char> decodedData(outputSize);

        // Second call to actually decode the data
        bResult = ::CryptStringToBinaryA(
            str.c_str(),
            static_cast<DWORD>(str.size()),
            CRYPT_STRING_BASE64,
            decodedData.data(),
            &outputSize,
            nullptr,
            nullptr
        );

        if (!bResult)
        {
            DWORD gle = ::GetLastError();
            HRESULT hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"Base64 decode failed during actual decoding: error=%d, hr=0x%X", gle, hrError);
            throw hrError;
        }

        // Ensure the vector has the correct size (in case outputSize changed)
        decodedData.resize(outputSize);

        LOG(Logger::VERBOSE, L"Successfully decoded %zu Base64 bytes to %u decoded bytes",
            str.length(), outputSize);

        return decodedData;
    }
    catch (const std::bad_alloc&) {
        // Handle memory allocation failures
        LOG(Logger::ERR, L"Memory allocation failed during Base64 decoding");
        throw E_OUTOFMEMORY;
    }
    catch (const HRESULT& hr) {
        // Re-throw HRESULT exceptions
        throw hr;
    }
    catch (...) {
        // Catch any other unexpected exceptions
        LOG(Logger::ERR, L"Unexpected exception during Base64 decoding");
        throw E_UNEXPECTED;
    }
}

// Extract value from a simple JSON string with robust error handling and validation
std::string GetValueFromJson(_In_ const std::string& json, _In_ const std::string& key)
{
    if (json.empty() || key.empty()) {
        LOG(Logger::WARN, L"GetValueFromJson called with empty %ls",
            json.empty() ? L"JSON" : L"key");
        throw E_UNEXPECTED;
    }

    // Format the search key with proper JSON syntax
    std::string searchKey = "\"" + key + "\":\"";
    std::size_t start = json.find(searchKey);

    // Handle case where key isn't found
    if (start == std::string::npos) {
        LOG(Logger::VERBOSE, L"JSON key '%ls' not found", UTF8ToWide(key).c_str());
        throw E_UNEXPECTED;
    }

    // Move past the key and opening quote to the value
    start += searchKey.length();

    // Find the closing quote
    std::size_t end = start;
    bool escaped = false;

    // Handle proper JSON string parsing with escape sequences
    while (end < json.length()) {
        char c = json[end];

        if (c == '\\' && !escaped) {
            escaped = true;
        }
        else if (c == '"' && !escaped) {
            // Found unescaped closing quote
            break;
        }
        else {
            escaped = false;
        }

        end++;
    }

    // Handle malformed JSON with missing closing quote
    if (end >= json.length()) {
        LOG(Logger::WARN, L"Malformed JSON: missing closing quote for key '%ls'",
            UTF8ToWide(key).c_str());
        throw E_UNEXPECTED;
    }

    // Extract the value
    return json.substr(start, end - start);
}

// Convert UTF-8 string to wide string with robust error handling and safety checks
std::wstring UTF8ToWide(_In_ const std::string& utf8Str)
{
    // Early return for empty strings
    if (utf8Str.empty()) {
        return L"";
    }

    try {
        // Calculate required buffer size
        int wideSizeRequired = MultiByteToWideChar(
            CP_UTF8,                // Code page: UTF-8
            MB_ERR_INVALID_CHARS,   // Error on invalid chars
            utf8Str.c_str(),        // Source UTF-8 string
            -1,                     // Null-terminated source
            nullptr,                // No output buffer yet
            0                       // Get required size
        );

        if (wideSizeRequired <= 0)
        {
            DWORD gle = GetLastError();
            HRESULT hrGle = HRESULT_FROM_WIN32(gle);

            // More detailed error information
            const wchar_t* errorType = (gle == ERROR_INVALID_PARAMETER) ? L"invalid parameters" :
                                      (gle == ERROR_NO_UNICODE_TRANSLATION) ? L"invalid UTF-8 sequence" :
                                      L"unknown error";

            LOG(Logger::ERR, L"UTF-8 conversion failed (%ls), error=%d, hr=0x%X",
                errorType, gle, hrGle);
            throw hrGle;
        }

        // Allocate string of appropriate size (-1 for null terminator that std::wstring doesn't need)
        std::wstring wideStr(wideSizeRequired - 1, 0);

        // Perform the conversion
        int wideSizeWritten = MultiByteToWideChar(
            CP_UTF8,                // Code page: UTF-8
            MB_ERR_INVALID_CHARS,   // Error on invalid chars
            utf8Str.c_str(),        // Source UTF-8 string
            -1,                     // Null-terminated source
            &wideStr[0],            // Output buffer
            wideSizeRequired        // Buffer size
        );

        if (wideSizeWritten <= 0)
        {
            DWORD gle = GetLastError();
            HRESULT hrGle = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"UTF-8 conversion failed during actual conversion, error=%d, hr=0x%X",
                gle, hrGle);
            throw hrGle;
        }

        return wideStr;
    }
    catch (const std::exception& e) {
        // Handle memory allocation failures
        LOGA(Logger::ERR, "UTF-8 conversion failed with exception: %s", e.what());
        throw HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
    }
}

// Class to manage LSA handle with RAII
class LSAHandle {
private:
    HANDLE m_handle;

public:
    LSAHandle() : m_handle(nullptr) {}

    ~LSAHandle() {
        Close();
    }

    HANDLE Get() const { return m_handle; }

    HRESULT Connect() {
        NTSTATUS status = ::LsaConnectUntrusted(&m_handle);
        if (status != 0) {
            HRESULT hr = HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
            LOG(Logger::ERR, L"LsaConnectUntrusted failed; ntstatus=%d, hr=0x%X", status, hr);
            return hr;
        }
        return S_OK;
    }

    void Close() {
        if (m_handle) {
            ::LsaDeregisterLogonProcess(m_handle);
            m_handle = nullptr;
        }
    }

    operator HANDLE() const { return m_handle; }
};

// Insert a Kerberos ticket into the cache
HRESULT InsertKerberosTicket(_In_ const unsigned char* kerberosTicket, _In_ size_t ticketLength)
{
    if (!kerberosTicket || ticketLength == 0) {
        LOG(Logger::ERR, L"Invalid ticket parameters");
        return E_INVALIDARG;
    }

    HRESULT hrError = S_OK;
    LSAHandle lsaHandle;
    PVOID pResponse = nullptr;
    ULONG responseSize = 0;
    KERB_SUBMIT_TKT_REQUEST* pSubmitRequest = nullptr;

    try
    {
        // Connect to LSA
        hrError = lsaHandle.Connect();
        if (FAILED(hrError)) {
            throw hrError;
        }

        // Lookup the Kerberos authentication package
        LSA_STRING packageName;
        ULONG authPackage;

        packageName.Buffer = const_cast<LPSTR>("Kerberos");
        packageName.Length = static_cast<USHORT>(strlen(packageName.Buffer));
        packageName.MaximumLength = packageName.Length + 1;

        NTSTATUS ntStatus = LsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPackage);
        if (ntStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaLookupAuthenticationPackage failed; ntstatus=%d, hr=0x%X", ntStatus, hrError);
            throw hrError;
        }

        // Allocate memory for the submit request
        size_t submitRequestSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + ticketLength;
        pSubmitRequest = static_cast<KERB_SUBMIT_TKT_REQUEST*>(HeapAlloc(GetProcessHeap(), 0, submitRequestSize));
        if (!pSubmitRequest)
        {
            hrError = E_OUTOFMEMORY;
            LOG(Logger::ERR, L"Failed to allocate KERB_SUBMIT_TKT_REQUEST. hr=0x%X", hrError);
            throw hrError;
        }

        // Initialize submit request
        LUID luidZero = {0, 0};
        pSubmitRequest->MessageType = KerbSubmitTicketMessage;
        pSubmitRequest->KerbCredSize = static_cast<ULONG>(ticketLength);
        pSubmitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
        pSubmitRequest->LogonId = luidZero;
        pSubmitRequest->Key.KeyType = 0;
        pSubmitRequest->Key.Length = 0;
        pSubmitRequest->Key.Offset = 0;

        // Copy ticket data
        memcpy(reinterpret_cast<BYTE*>(pSubmitRequest) + pSubmitRequest->KerbCredOffset,
               kerberosTicket, ticketLength);

        // Submit the ticket with retries
        const DWORD MAX_RETRIES = 3;
        DWORD dwRetriesLeft = MAX_RETRIES;
        NTSTATUS ntProtocolStatus = 0;

        do
        {
            // Free any previous response
            if (pResponse)
            {
                LsaFreeReturnBuffer(pResponse);
                pResponse = nullptr;
                responseSize = 0;
            }

            // Call authentication package
            ntStatus = ::LsaCallAuthenticationPackage(
                lsaHandle,
                authPackage,
                pSubmitRequest,
                static_cast<ULONG>(submitRequestSize),
                &pResponse,
                &responseSize,
                &ntProtocolStatus
            );

            if ((ntStatus == 0) && (ntProtocolStatus == 0))
            {
                // Success
                break;
            }

            // Log error and retry
            if (ntStatus != 0)
            {
                hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed; ntstatus=%d, hr=0x%X, retries left: %d",
                    ntStatus, hrError, dwRetriesLeft - 1);
            }

            if (ntProtocolStatus != 0)
            {
                hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntProtocolStatus));
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage succeeded but insertion failed; ntstatus=%d, hr=0x%X, retries left: %d",
                    ntProtocolStatus, hrError, dwRetriesLeft - 1);
            }

            // Wait before retry
            ::Sleep(500);
            dwRetriesLeft--;

        } while (dwRetriesLeft > 0);

        // Handle final errors
        if (ntStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed after %d retries; ntstatus=%d, hr=0x%X",
                MAX_RETRIES, ntStatus, hrError);
            throw hrError;
        }

        if (ntProtocolStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntProtocolStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage succeeded but insertion failed after %d retries; ntstatus=%d, hr=0x%X",
                MAX_RETRIES, ntProtocolStatus, hrError);
            throw hrError;
        }
    }
    catch (const std::exception& e)
    {
        hrError = E_UNEXPECTED;
        LOGA(Logger::ERR, "Generic exception '%s' hr=0x%X.", e.what(), hrError);
    }
    catch (const HRESULT& caughtHr)
    {
        hrError = caughtHr;
    }

    // Clean up resources
    if (pSubmitRequest)
    {
        HeapFree(GetProcessHeap(), 0, pSubmitRequest);
    }

    if (pResponse)
    {
        LsaFreeReturnBuffer(pResponse);
    }

    return hrError;
}

// Display or purge a Kerberos ticket from the cache
HRESULT DisplayKerbTicket(_In_ PCWSTR pwszTargetName, _In_ bool bPurge)
{
    if (!pwszTargetName || pwszTargetName[0] == L'\0') {
        return E_INVALIDARG;
    }

    HRESULT hrError = S_OK;
    LSAHandle lsaHandle;
    KERB_RETRIEVE_TKT_REQUEST* pTktCacheRequest = nullptr;
    KERB_RETRIEVE_TKT_RESPONSE* pTktCacheResponse = nullptr;
    PVOID purgeResponse = nullptr;
    KERB_PURGE_TKT_CACHE_REQUEST* pTktPurgeRequest = nullptr;

    try
    {
        // Connect to LSA
        hrError = lsaHandle.Connect();
        if (FAILED(hrError)) {
            throw hrError;
        }

        // Lookup the Kerberos authentication package
        LSA_STRING packageName;
        packageName.Buffer = const_cast<LPSTR>("Kerberos");
        packageName.Length = static_cast<USHORT>(strlen(packageName.Buffer));
        packageName.MaximumLength = packageName.Length + 1;

        ULONG authPackage;
        NTSTATUS ntStatus = ::LsaLookupAuthenticationPackage(lsaHandle, &packageName, &authPackage);
        if (ntStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaLookupAuthenticationPackage failed hr=0x%X.", hrError);
            throw hrError;
        }

        // Calculate target name size and allocate request buffer
        DWORD dwTargetNameSizeBytes = static_cast<DWORD>(wcslen(pwszTargetName) * sizeof(wchar_t));
        pTktCacheRequest = static_cast<KERB_RETRIEVE_TKT_REQUEST*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTargetNameSizeBytes + sizeof(KERB_RETRIEVE_TKT_REQUEST))
        );

        if (!pTktCacheRequest) {
            hrError = E_OUTOFMEMORY;
            LOG(Logger::ERR, L"Failed to allocate memory for KERB_RETRIEVE_TKT_REQUEST");
            throw hrError;
        }

        // Set up the ticket retrieval request
        pTktCacheRequest->MessageType = KerbRetrieveEncodedTicketMessage;
        pTktCacheRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
        pTktCacheRequest->LogonId.LowPart = 0;
        pTktCacheRequest->LogonId.HighPart = 0;

        // Set up the target name buffer
        LSA_UNICODE_STRING oTargetBuff = { 0 };
        oTargetBuff.Buffer = reinterpret_cast<LPWSTR>(pTktCacheRequest + 1);
        oTargetBuff.Length = static_cast<USHORT>(dwTargetNameSizeBytes);
        oTargetBuff.MaximumLength = static_cast<USHORT>(dwTargetNameSizeBytes);

        // Copy the target name
        memcpy(oTargetBuff.Buffer, pwszTargetName, dwTargetNameSizeBytes);
        pTktCacheRequest->TargetName = oTargetBuff;

        // Call LSA to retrieve the ticket
        NTSTATUS ntSubStatus;
        DWORD dwResponseSize = 0;
        DWORD dwSubmitBufferLen = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTargetNameSizeBytes;

        ntStatus = LsaCallAuthenticationPackage(
            lsaHandle,
            authPackage,
            pTktCacheRequest,
            dwSubmitBufferLen,
            reinterpret_cast<void**>(&pTktCacheResponse),
            &dwResponseSize,
            &ntSubStatus
        );

        if (ntStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage failed hr=0x%X.", hrError);
            throw hrError;
        }

        if (ntSubStatus != 0)
        {
            hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntSubStatus));
            LOG(Logger::ERR, L"LsaCallAuthenticationPackage (ProtocolStatus) failed hr=0x%X.", hrError);
            throw hrError;
        }

        // Log the ticket information
        LOG(Logger::INFO, L"----------------------------------%ls----------------------------------", pwszTargetName);

        if (pTktCacheResponse && pTktCacheResponse->Ticket.ClientName && pTktCacheResponse->Ticket.ClientName->Names) {
            LOG(Logger::INFO, L"Client : %.*s @ %.*s",
                static_cast<DWORD>(pTktCacheResponse->Ticket.ClientName->Names->Length / sizeof(WCHAR)),
                pTktCacheResponse->Ticket.ClientName->Names->Buffer,
                static_cast<DWORD>(pTktCacheResponse->Ticket.DomainName.Length / sizeof(WCHAR)),
                pTktCacheResponse->Ticket.DomainName.Buffer);
        }

        if (pTktCacheResponse && pTktCacheResponse->Ticket.TargetName && pTktCacheResponse->Ticket.TargetName->Names) {
            LOG(Logger::INFO, L"Target : %.*s @ %.*s",
                static_cast<DWORD>(pTktCacheResponse->Ticket.TargetName->Names->Length / sizeof(WCHAR)),
                pTktCacheResponse->Ticket.TargetName->Names->Buffer,
                static_cast<DWORD>(pTktCacheResponse->Ticket.TargetDomainName.Length / sizeof(WCHAR)),
                pTktCacheResponse->Ticket.TargetDomainName.Buffer);
        }

        if (pTktCacheResponse && pTktCacheResponse->Ticket.ServiceName && pTktCacheResponse->Ticket.ServiceName->Names) {
            LOG(Logger::INFO, L"Service: %.*s",
                static_cast<DWORD>(pTktCacheResponse->Ticket.ServiceName->Names->Length / sizeof(WCHAR)),
                pTktCacheResponse->Ticket.ServiceName->Names->Buffer);
        }

        // Purge the ticket if requested
        if (bPurge)
        {
            // Allocate memory for purge request
            pTktPurgeRequest = static_cast<KERB_PURGE_TKT_CACHE_REQUEST*>(
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTargetNameSizeBytes + sizeof(KERB_PURGE_TKT_CACHE_REQUEST))
            );

            if (!pTktPurgeRequest) {
                hrError = E_OUTOFMEMORY;
                LOG(Logger::ERR, L"Failed to allocate memory for KERB_PURGE_TKT_CACHE_REQUEST");
                throw hrError;
            }

            // Set up the purge request
            LSA_UNICODE_STRING oTargetBuff2 = { 0 };
            oTargetBuff2.Buffer = reinterpret_cast<LPWSTR>(pTktPurgeRequest + 1);
            oTargetBuff2.Length = static_cast<USHORT>(dwTargetNameSizeBytes);
            oTargetBuff2.MaximumLength = static_cast<USHORT>(dwTargetNameSizeBytes);

            memcpy(oTargetBuff2.Buffer, pwszTargetName, dwTargetNameSizeBytes);
            pTktPurgeRequest->ServerName = oTargetBuff2;
            pTktPurgeRequest->LogonId.LowPart = 0;
            pTktPurgeRequest->LogonId.HighPart = 0;
            pTktPurgeRequest->MessageType = KerbPurgeTicketCacheMessage;

            DWORD dwSubmitBufferLen2 = sizeof(KERB_PURGE_TKT_CACHE_REQUEST) + dwTargetNameSizeBytes;
            ULONG responseSize = 0;

            // Call the LSA function to purge the ticket
            ntStatus = LsaCallAuthenticationPackage(
                lsaHandle,
                authPackage,
                pTktPurgeRequest,
                dwSubmitBufferLen2,
                &purgeResponse,
                &responseSize,
                &ntSubStatus
            );

            if (ntStatus != 0)
            {
                hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntStatus));
                LOG(Logger::ERR, L"LsaCallAuthenticationPackage hr=0x%X", hrError);
                throw hrError;
            }

            if (ntSubStatus != 0)
            {
                hrError = HRESULT_FROM_WIN32(LsaNtStatusToWinError(ntSubStatus));
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
    catch (const HRESULT& caughtHr)
    {
        hrError = caughtHr;
    }

    // Clean up resources
    if (pTktCacheRequest)
    {
        HeapFree(GetProcessHeap(), 0, pTktCacheRequest);
    }

    if (pTktCacheResponse)
    {
        LsaFreeReturnBuffer(pTktCacheResponse);
    }

    if (pTktPurgeRequest)
    {
        HeapFree(GetProcessHeap(), 0, pTktPurgeRequest);
    }

    if (purgeResponse)
    {
        LsaFreeReturnBuffer(purgeResponse);
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
    DWORD   sc = 0;
    HRESULT hr = S_OK;
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

HRESULT HTTPStatusToHresult(_In_ DWORD sc)
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

// Helper class to manage WinHTTP handles with RAII
class WinHttpHandle {
private:
    HINTERNET m_handle;

    // Prevent copy
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

public:
    WinHttpHandle() : m_handle(nullptr) {}

    // Move constructor
    WinHttpHandle(WinHttpHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    // Move assignment
    WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
        if (this != static_cast<void*>(&other)) {
            if (m_handle) {
                WinHttpCloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    ~WinHttpHandle() {
        Close();
    }

    void Close() {
        if (m_handle) {
            WinHttpCloseHandle(m_handle);
            m_handle = nullptr;
        }
    }

    void Set(HINTERNET handle) {
        Close();
        m_handle = handle;
    }

    bool IsValid() const { return m_handle != nullptr; }

    operator HINTERNET() const { return m_handle; }

    HINTERNET* operator&() {
        Close();
        return &m_handle;
    }
};

// Improved HTTP request handling with better resource management
HRESULT DoHttpVerb(
    _In_      const std::wstring& verb,
    _In_      const std::wstring& requestUrl,
    _In_opt_  const std::wstring& oauthToken,
    _Out_     std::string& winhttpResponse)
{
    LOG(Logger::VERBOSE, L"BEGIN");

    // Use RAII for proper resource cleanup
    WinHttpHandle hSession;
    WinHttpHandle hConnect;
    WinHttpHandle hRequest;
    HRESULT hrError = S_OK;

    winhttpResponse.clear();

    try
    {        // Parse the URL components
        URL_COMPONENTS urlComp = {0};
        urlComp.dwStructSize = sizeof(urlComp);
        wchar_t hostName[256] = {};
        wchar_t urlPath[256] = {};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);

        if (!WinHttpCrackUrl(requestUrl.c_str(), 0, 0, &urlComp))
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpCrackUrl failed, URL %ls, hr=0x%X", requestUrl.c_str(), hrError);
            throw hrError;
        }
        // Determine protocol and validate input
        bool bUseHttps = false;
        bool bIsIMDSQuery = false;

        LOG(Logger::INFO, L"%ls %ls", verb.c_str(), requestUrl.c_str());

        // Protocol detection and validation
        if (requestUrl.compare(0, 8, L"https://") == 0)
        {
            bUseHttps = true;
            if (oauthToken.empty())
            {
                LOG(Logger::ERR, L"OAuth token is required for HTTPS requests: %ls", requestUrl.c_str());
                throw E_INVALIDARG;
            }
        }
        else if (requestUrl.compare(0, 7, L"http://") == 0)
        {
            bUseHttps = false;
            if (!oauthToken.empty())
            {
                LOG(Logger::ERR, L"OAuth token should not be provided for HTTP requests: %ls", requestUrl.c_str());
                throw E_INVALIDARG;
            }

            if (requestUrl.compare(0, 22, L"http://169.254.169.254") == 0)
            {
                bIsIMDSQuery = true;
            }
        }
        else
        {
            LOG(Logger::ERR, L"URL must begin with 'http://' or 'https://': %ls", requestUrl.c_str());
            throw E_INVALIDARG;
        }

        // Open a WinHTTP session with proper error handling
        hSession.Set(WinHttpOpen(L"AzureFilesSmbMIAuth",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME,
                               WINHTTP_NO_PROXY_BYPASS,
                               0));
        if (!hSession)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"Failed to open WinHTTP session for %ls, hr=0x%X", requestUrl.c_str(), hrError);
            throw hrError;
        }

        // Specify the target server
        HINTERNET tempConnect = WinHttpConnect(hSession,
                                            urlComp.lpszHostName,
                                            bUseHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
                                            0);
        if (!tempConnect)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpConnect, server %ls, hr=0x%X",  requestUrl.c_str(), hrError);
            throw hrError;
        }
        hConnect.Set(tempConnect);

        // Create an HTTP request handle
        HINTERNET tempRequest = WinHttpOpenRequest(hConnect,
                                        verb.c_str(),
                                        urlComp.lpszUrlPath,
                                        bUseHttps ? L"HTTP/2" : nullptr,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        bUseHttps ? WINHTTP_FLAG_SECURE : 0);
        if (!tempRequest)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpOpenRequest(%ls), server %ls, hr=0x%X", verb.c_str(), requestUrl.c_str(), hrError);
            throw hrError;
        }
        hRequest.Set(tempRequest);

        if (!hRequest)
        {
            hrError = HRESULT_FROM_WIN32(::GetLastError());
            LOG(Logger::ERR, L"WinHttpOpenRequest(%ls), server %ls, hr=0x%X", verb.c_str(), requestUrl.c_str(), hrError);
            throw hrError;
        }

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
        BOOL bResult = FALSE;

        if (bIsIMDSQuery)
        {
             std::wstring headers = L"Metadata: true\r\n";

            // Send the request for IMDS query
            bResult = WinHttpSendRequest(hRequest,
                                         headers.c_str(),
                                         static_cast<DWORD>(headers.size()),
                                         WINHTTP_NO_REQUEST_DATA,
                                         0,
                                         0,
                                         0);
        }
        else
        {
            // For Azure Storage requests, add required headers
            bResult = ::WinHttpAddRequestHeaders(hRequest,
                                                 wstrApiVersion.c_str(),
                                                 static_cast<DWORD>(-1L),
                                                 WINHTTP_ADDREQ_FLAG_ADD);

            if (!bResult)
            {
                hrError = HRESULT_FROM_WIN32(::GetLastError());
                LOG(Logger::ERR, L"Failed to add API version header for %ls, hr=0x%X", requestUrl.c_str(), hrError);
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
                                         nullptr);
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

        LOG(Logger::INFO, L"http status=%d", dwStatusCode);        // Read the response data (even in error cases)
        // Reserve space in the response string to minimize reallocations
        winhttpResponse.reserve(4096);  // Reserve reasonable initial capacity

        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;

        do
        {
            // Query available data size
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                DWORD gle = GetLastError();
                hrError = HRESULT_FROM_WIN32(gle);
                LOG(Logger::ERR, L"Failed to query available data from %ls, error=%d, hr=0x%X",
                    requestUrl.c_str(), gle, hrError);
                throw hrError;
            }

            if (dwSize == 0)
                break;  // No more data available

            // Use smart pointer for automatic cleanup
            std::unique_ptr<char[]> responseBuffer(new (std::nothrow) char[dwSize + 1]);
            if (!responseBuffer)
            {
                hrError = E_OUTOFMEMORY;
                LOG(Logger::ERR, L"Failed to allocate memory for HTTP response from %ls, hr=0x%X",
                    requestUrl.c_str(), hrError);
                throw hrError;
            }

            // Ensure null-termination
            ZeroMemory(responseBuffer.get(), dwSize + 1);

            // Read data into buffer
            if (!WinHttpReadData(hRequest,
                                responseBuffer.get(),
                                dwSize,
                                &dwDownloaded))
            {
                DWORD gle = GetLastError();
                hrError = HRESULT_FROM_WIN32(gle);
                LOG(Logger::ERR, L"Failed to read HTTP response data from %ls, error=%d, hr=0x%X",
                    requestUrl.c_str(), gle, hrError);
                throw hrError;
            }

            // Append data to response string
            winhttpResponse.append(responseBuffer.get(), dwDownloaded);

        } while (dwSize > 0);  // Continue until no more data        // Handle non-success HTTP status codes

        if ((dwStatusCode < 200) || (dwStatusCode > 299))
        {
            std::unique_ptr<wchar_t[]> headers = GetAllResponseHeaders(hRequest);
            hrError = HTTPStatusToHresult(dwStatusCode);

            // Log both headers and response body for better diagnostics
            LOG(Logger::ERR, L"HTTP request failed: %ls, Status=%d, hr=0x%X",
                requestUrl.c_str(), dwStatusCode, hrError);

            if (headers) {
                LOG(Logger::ERR, L"Response headers: %ls", headers.get());
            }

            // Limit response body logging to avoid excessive log entries
            const size_t maxResponseToLog = 1024;
            std::string truncatedResponse = winhttpResponse;
            if (truncatedResponse.length() > maxResponseToLog) {
                truncatedResponse = truncatedResponse.substr(0, maxResponseToLog) + "...";
            }

            LOGA(Logger::ERR, "Response body (possibly truncated): %s", truncatedResponse.c_str());
            throw hrError;
        }

        LOG(Logger::INFO, L"HTTP request succeeded: %ls", requestUrl.c_str());
    }
    catch (const std::exception& e)
    {
        // More descriptive logging for std::exception
        LOGA(Logger::ERR, "HTTP request failed with exception: %s", e.what());
        hrError = E_FAIL;
    }
    catch (const HRESULT& caughtHr)
    {
        // Already captured the error code, just ensure it's preserved
        hrError = caughtHr;
    }
    catch (...)
    {
        // Catch all unexpected exceptions
        LOG(Logger::ERR, L"HTTP request failed with unexpected exception");
        if (SUCCEEDED(hrError)) {
            hrError = E_UNEXPECTED;
        }
    }

    // The WinHttpHandle class destructor will automatically clean up resources
    // No manual cleanup needed thanks to RAII

    LOG(Logger::VERBOSE, L"END with hr=0x%X", hrError);
    return hrError;
}

std::string GetCurrentTimeISO8601()
{
    // Get the current time in system_clock (UTC)
    auto now = std::chrono::system_clock::now();
    auto time_point = std::chrono::system_clock::to_time_t(now);

    std::tm tm_time{};
    gmtime_s(&tm_time, &time_point);

    // Format the time into an ISO 8601 string
    std::ostringstream oss;
    oss << std::put_time(&tm_time, "%Y-%m-%dT%H:%M:%S");

    return oss.str();
}

// Calculate elapsed seconds from a given timestamp with improved error handling and logging
DWORD ElapsedSecondsFromNow(_In_ const std::string& timestamp)
{
    try {
        if (timestamp.empty()) {
            LOGA(Logger::ERR, "Empty timestamp provided for calculation");
            throw std::invalid_argument("Empty timestamp provided");
        }

        // Log the calculation request
        LOGA(Logger::VERBOSE, "Calculating time difference from now to %s", timestamp.c_str());

        // Parse the timestamp into struct tm using safer approach
        std::tm tm_time = {};
        std::istringstream ss(timestamp);
        ss >> std::get_time(&tm_time, "%Y-%m-%dT%H:%M:%S");

        if (ss.fail()) {
            LOGA(Logger::ERR, "Failed to parse timestamp '%s' with format %%Y-%%m-%%dT%%H:%%M:%%S",
                 timestamp.c_str());
            throw std::runtime_error("Failed to parse timestamp");
        }

        // Basic validation of parsed time
        if (tm_time.tm_year < 100 || // Year starts from 1900
            tm_time.tm_mon < 0 || tm_time.tm_mon > 11 ||
            tm_time.tm_mday < 1 || tm_time.tm_mday > 31 ||
            tm_time.tm_hour < 0 || tm_time.tm_hour > 23 ||
            tm_time.tm_min < 0 || tm_time.tm_min > 59 ||
            tm_time.tm_sec < 0 || tm_time.tm_sec > 60) { // Allow for leap second

            LOGA(Logger::ERR, "Invalid timestamp values in '%s'", timestamp.c_str());
            throw std::runtime_error("Invalid timestamp values");
        }

        // Convert to time_t (represents local time)
        std::time_t local_time = std::mktime(&tm_time);
        if (local_time == -1) {
            LOGA(Logger::ERR, "Failed to convert timestamp '%s' to time_t", timestamp.c_str());
            throw std::runtime_error("Invalid timestamp conversion");
        }

        // Get timezone offset
        long timezone_seconds;
        auto err = _get_timezone(&timezone_seconds);
        if (err != 0) {
            LOGA(Logger::ERR, "Failed to get timezone offset, error=%d", err);
            throw std::runtime_error("Failed to get timezone offset");
        }

        // Convert to UTC by subtracting the timezone offset
        std::time_t time_stamp_t = local_time - timezone_seconds;

        // Get current UTC time
        std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

        // Compute difference in seconds
        double diff_seconds = std::difftime(time_stamp_t, now);

        // Handle corner cases
        if (diff_seconds > UINT_MAX) {
            LOGA(Logger::WARN, "Time difference exceeds DWORD limit, capping to UINT_MAX");
            return UINT_MAX;
        }

        if (diff_seconds < 0) {
            // This means the timestamp is in the past
            LOGA(Logger::INFO, "Timestamp is in the past by %.2f seconds", -diff_seconds);
            return 0; // Return 0 for expired timestamps
        }

        LOGA(Logger::INFO, "Timestamp expires in %.2f seconds", diff_seconds);
        return static_cast<DWORD>(diff_seconds);
    }
    catch (const std::exception& e) {
        LOGA(Logger::ERR, "Exception in ElapsedSecondsFromNow: %s", e.what());
        // Re-throw with additional context
        throw std::runtime_error(std::string("Time calculation error: ") + e.what());
    }
}

HRESULT SmbSetCredentialInternal(
    _In_      PCWSTR pwszFileEndpointUri,
    _In_opt_  PCWSTR pwszOauthToken,
    _In_opt_  PCWSTR pwszClientID,
    _Out_     PDWORD pdwCredentialExpiresInSeconds
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
        if (pwszFileEndpointUri == nullptr || pwszFileEndpointUri[0] == L'\0') {
            LOG(Logger::ERR, L"File URI cannot be null or empty.");
            throw E_INVALIDARG;
        }

        if (pdwCredentialExpiresInSeconds == nullptr) {
            LOG(Logger::ERR, L"Output parameter pdwCredentialExpiresInSeconds cannot be null.");
            throw E_INVALIDARG;
        }

        std::wstring wstrAccountFileUri = pwszFileEndpointUri;

        if (wstrAccountFileUri[wstrAccountFileUri.length() - 1] != L'/') {
            LOG(Logger::ERR, L"File URI '%ls' is not ending with trailing '/'", wstrAccountFileUri.c_str());
            throw E_INVALIDARG;
        }

        if (wstrAccountFileUri.substr(0, 8) != L"https://") {
            LOG(Logger::ERR, L"File URI '%ls' is not prefixed with 'https://'", wstrAccountFileUri.c_str());
            throw E_INVALIDARG;
        }

        BOOL bGetTokenFromImds = ((pwszOauthToken == nullptr) || (pwszOauthToken[0] == L'\0'));
        LOG(Logger::INFO, L"Authenticating access to '%ls' %ls", wstrAccountFileUri.c_str(),
            bGetTokenFromImds ? (pwszClientID && (pwszClientID[0] != L'\0') ?
                L"by fetching OAuth token from IMDS endpoint using user-managed identity" :
                L"by fetching OAuth token from IMDS endpoint using system-managed identity") :
            L"using provided OAuth token");

        std::string strHttpResponse;
        std::wstring wstrAccessToken;

        if (bGetTokenFromImds)
        {
            // Get token for resource=https://storage.azure.com.  Note that there is NO trailing '/'.
            // OK     --> resource=https://storage.azure.com
            // NOT OK --> resource=https://storage.azure.com/
            // Build the IMDS request URL with optional client ID
            std::wstring imdsUrl = L"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com";

            // Add client ID parameter if provided
            if (pwszClientID && pwszClientID[0] != L'\0') 
            {
                imdsUrl += L"&client_id=";
                imdsUrl += pwszClientID;
                LOG(Logger::INFO, L"Using user-managed identity with client ID: %ls", pwszClientID);
            }
            else
            {
                LOG(Logger::INFO, L"Using system-managed identity (no client ID specified)");
            }

            hrError = DoHttpVerb(L"GET", imdsUrl, L"", strHttpResponse);

            if (FAILED(hrError))
            {
                LOG(Logger::ERR, L"GET %ls failed with error hr=0x%X", imdsUrl.c_str(), hrError);
                throw hrError;
            }

            std::string access_tokenstr = GetValueFromJson(strHttpResponse, "access_token");
            wstrAccessToken = UTF8ToWide(access_tokenstr);
            strHttpResponse.clear();
        }
        else
        {
            wstrAccessToken = pwszOauthToken;
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
        std::vector<unsigned char> decodedTicket = FromBase64(kerbTicket);

        LOGA(Logger::INFO, "SessionKey: '%s'", sessionKey.c_str());
        LOGA(Logger::INFO, "ExpirationTime: '%s'", expiration.c_str());

        DWORD dwExpiresInSeconds = ElapsedSecondsFromNow(expiration);
        LOGA(Logger::INFO, "Expires in: '%d' seconds from now (%s)", dwExpiresInSeconds, GetCurrentTimeISO8601().c_str());
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

VOID CALLBACK SmbRefreshTimerCallback(
    _In_      PTP_CALLBACK_INSTANCE Instance,
    _In_      PVOID Context,
    _In_      PTP_TIMER /*Timer*/)
{
    UNREFERENCED_PARAMETER(Instance);
    RefreshContext* pContext = (RefreshContext*)Context;

    DWORD dwCredentialExpiresInSeconds;
    HRESULT hrError = SmbSetCredentialInternal(
        pContext->wstrFileEndpointUri.c_str(),
        nullptr,
        pContext->wstrClientID.empty() ? nullptr : pContext->wstrClientID.c_str(),
        &dwCredentialExpiresInSeconds);

    if (FAILED(hrError))
    {
        LOG(Logger::ERR, L"SmbSetCredentialInternal hr=0x%X", hrError);
        pContext->hrRefresh = hrError;
        return;
    }

    ::SetEvent(pContext->shEvent.get());  // Signal main thread that we're done

    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(static_cast<LONGLONG>(dwCredentialExpiresInSeconds * 1000 * 1000 * 10));

    FILETIME ftDueTime;
    ftDueTime.dwLowDateTime = liDueTime.LowPart;
    ftDueTime.dwHighDateTime = liDueTime.HighPart;

    // Set the timer to fire after dwCredentialExpiresInSeconds seconds.
    ::SetThreadpoolTimer(pContext->timer, &ftDueTime, 0, 0);
}

HRESULT SmbRefreshCredentialInternal(
    _In_      PCWSTR pwszFileEndpointUri,
    _In_      PCWSTR pwszClientID
    )
{
    // Initialize logger first
    s_logger.Initialize();

    LOG(Logger::VERBOSE, L"BEGIN");

    HRESULT hrError = S_OK;
    try
    {
        if (pwszFileEndpointUri == nullptr || pwszFileEndpointUri[0] == L'\0') {
            LOG(Logger::ERR, L"File URI cannot be null or empty.");
            throw E_INVALIDARG;
        }

        if (pwszFileEndpointUri[wcslen(pwszFileEndpointUri) - 1] != L'/') {
            LOG(Logger::ERR, L"File URI '%ls' is not ending with trailing '/'", pwszFileEndpointUri);
            throw E_INVALIDARG;
        }

        auto ctx = std::make_shared<RefreshContext>(pwszFileEndpointUri, pwszClientID);

        ctx->shEvent.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!ctx->shEvent) {
            DWORD dwError = GetLastError();
            hrError = HRESULT_FROM_WIN32(dwError);
            LOG(Logger::ERR, L"CreateEvent failed with error %d", dwError);
            throw hrError;
        }

        ctx->timer = CreateThreadpoolTimer(SmbRefreshTimerCallback, ctx.get(), nullptr);
        if (!ctx->timer) {
            DWORD gle = ::GetLastError();
            hrError = HRESULT_FROM_WIN32(gle);
            LOG(Logger::ERR, L"CreateThreadpoolTimer failed hr=0x%X", hrError);
            throw hrError;
        }

        {
            std::lock_guard<std::mutex> lock(timerMapMutex);
            auto result = s_timerMap.insert_or_assign(std::wstring(pwszFileEndpointUri), ctx);
            LOG(Logger::INFO, L"%ls refresh registration for %ls", result.second ? L"Created" : L"Updated", pwszFileEndpointUri);
        }

        FILETIME ftDueTime;
        ftDueTime.dwLowDateTime = 0;
        ftDueTime.dwHighDateTime = 0;

        // Set the timer to fire immediately
        ::SetThreadpoolTimer(ctx->timer, &ftDueTime, 0, 0);

        // Wait for the callback to signal completion of the first refresh
        ::WaitForSingleObject(ctx->shEvent.get(), INFINITE);
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

HRESULT SmbClearCredentialInternal(
    _In_  PCWSTR pwszFileEndpointUri
    )
{
    // Initialize logger first
    s_logger.Initialize();

    LOG(Logger::VERBOSE, L"BEGIN");

    HRESULT hrError = S_OK;
    try
    {
        if (pwszFileEndpointUri == nullptr || pwszFileEndpointUri[0] == L'\0') {
            LOG(Logger::ERR, L"File URI cannot be null or empty.");
            throw E_INVALIDARG;
        }

        if (pwszFileEndpointUri[wcslen(pwszFileEndpointUri) - 1] != L'/') {
            LOG(Logger::ERR, L"File URI '%ls' is not ending with trailing '/'", pwszFileEndpointUri);
            throw E_INVALIDARG;
        }

        // Clean up refresh timers if any
        {
            std::lock_guard<std::mutex> lock(timerMapMutex);
            auto it = s_timerMap.find(pwszFileEndpointUri);
            if (it != s_timerMap.end())
            {
                ::WaitForThreadpoolTimerCallbacks(it->second->timer, TRUE);
                ::CloseThreadpoolTimer(it->second->timer);
                s_timerMap.erase(it);
                LOG(Logger::INFO, L"Stopped and removed refresh timer for %ls", pwszFileEndpointUri);
            }
        }

        std::wstring wstrFileUri = pwszFileEndpointUri;
        wstrFileUri.pop_back(); // removing trailing '/'
        wstrFileUri = wstrFileUri.substr(8);   // remove https://
        wstrFileUri = L"cifs/" + wstrFileUri;  // append cifs/

        hrError = DisplayKerbTicket(wstrFileUri.c_str(), true /*bPurge*/);
        if (FAILED(hrError))
        {
            throw hrError;
        }

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

HRESULT SmbSetCredential(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_  PCWSTR pwszOauthToken,
    _In_  PCWSTR pwszClientID,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
)
{
    return SmbSetCredentialInternal(pwszFileEndpointUri, pwszOauthToken, pwszClientID, pdwCredentialExpiresInSeconds);
}

HRESULT SmbRefreshCredential(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_opt_  PCWSTR pwszClientID
)
{
    return SmbRefreshCredentialInternal(pwszFileEndpointUri, pwszClientID);
}

HRESULT SmbClearCredential(
    _In_  PCWSTR pwszFileEndpointUri
)
{
    return SmbClearCredentialInternal(pwszFileEndpointUri);
}