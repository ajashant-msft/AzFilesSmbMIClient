// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the AZUREFILESSMBAUTH_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// AZUREFILESSMBAUTH_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef AZUREFILESSMBAUTH_EXPORTS
#define AZUREFILESSMBAUTH_API __declspec(dllexport)
#else
#define AZUREFILESSMBAUTH_API __declspec(dllimport)
#endif

extern AZUREFILESSMBAUTH_API int nAzureFilesSmbAuth;

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbSetCredential(
    _In_  PCWSTR pwszFileEndpointUri,
    _In_  PCWSTR pwszOauthToken,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
);

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbSetCredentialUsingTokenFromIMDS(
    _In_  PCWSTR pwszFileEndpointUri,
    _Out_ PDWORD pdwCredentialExpiresInSeconds
);

extern "C" AZUREFILESSMBAUTH_API HRESULT SmbClearCredential(
    _In_  PCWSTR pwszFileEndpointUri
);

HRESULT SmbSetCredentialInternal(
    _In_      PCWSTR pwszFileEndpointUri,
    _In_opt_  PCWSTR pwszOauthToken,
    _Out_     PDWORD pdwCredentialExpiresInSeconds
    );

HRESULT SmbClearCredentialInternal(
    _In_  PCWSTR pwszFileEndpointUri
    );