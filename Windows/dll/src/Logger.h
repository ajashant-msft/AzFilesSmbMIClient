/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    Logger.cpp

Abstract:

    C++ class that implements logging for this dll.

--*/

#pragma once
class Logger
{
public:
    enum LogLevel
    {
        NONE,
        ERR,
        WARN,
        INFO,
        VERBOSE
    };

    Logger();
    void Initialize();

    ~Logger();

    void log(_In_ PCWSTR pwszFunction, _In_ DWORD dwLine, _In_ LogLevel level, _In_ PCWSTR pszFormat, ...);
    void log(_In_ PCSTR pszFunction, _In_ DWORD dwLine, _In_ LogLevel level, _In_ PCSTR pszFormat, ...);
    void ensureLogFileExists();

private:
    std::wstring   logFilePath_;
    std::wofstream logFile_;
    LogLevel       verbosityLevel_;
    std::mutex     mutex_;
    bool           loggerInitialized_;

    void         loadVerbosityFromRegistry(_In_ const std::wstring& registryKeyPath);
    std::wstring getTimestamp();
    LogLevel     verbosityToLogLevel(_In_ DWORD verbosity);
    std::wstring logLevelToString(_In_ LogLevel level);
};