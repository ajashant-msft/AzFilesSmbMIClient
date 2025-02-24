// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "AzureFilesSmbAuth.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbSetCredential(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_  PCWSTR pwszOauthToken,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
    )
{
    return SmbSetCredentialInternal(pwszFileEndpointUri, pwszOauthToken, pdwCredentialExpiresInSeconds);
}

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbClearCredential(
    _In_  PCWSTR pwszFileEndpointUri
    )
{
    return SmbShowOrClearCredentialInternal(true /*clear*/, pwszFileEndpointUri);
}

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbShowCredential(
    _In_  PCWSTR pwszFileEndpointUri
    )
{
    return SmbShowOrClearCredentialInternal(false /*clear*/, pwszFileEndpointUri);
}