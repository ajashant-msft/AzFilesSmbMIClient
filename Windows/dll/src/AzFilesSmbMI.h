/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    AzFilesSmbMI.h: Declares the exported functions for the DLL.

--*/

// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the AZFILESSMBMI_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// AZFILESSMBMI_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef AZFILESSMBMI_EXPORTS
#define AZFILESSMBMI_API __declspec(dllexport)
#else
#define AZFILESSMBMI_API __declspec(dllimport)
#endif

extern AZFILESSMBMI_API int nAzFilesSmbMI;

extern "C" AZFILESSMBMI_API HRESULT SmbSetCredential(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_  PCWSTR pwszOauthToken,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
    );

extern "C" AZFILESSMBMI_API HRESULT SmbRefreshCredential(
    _In_ PCWSTR pwszFileEndpointUri
    );

extern "C" AZFILESSMBMI_API HRESULT SmbClearCredential(
    _In_ PCWSTR pwszFileEndpointUri
    );

HRESULT SmbSetCredentialInternal(
    _In_      PCWSTR pwszFileEndpointUri,
    _In_opt_  PCWSTR pwszOauthToken,
    _Out_     PDWORD pdwCredentialExpiresInSeconds
    );

HRESULT SmbRefreshCredentialInternal(
    _In_      PCWSTR pwszFileEndpointUri
    );

HRESULT SmbClearCredentialInternal(
    _In_  PCWSTR pwszFileEndpointUri
    );