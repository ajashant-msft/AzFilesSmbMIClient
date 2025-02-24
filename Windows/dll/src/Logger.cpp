#include "pch.h"
#include <strsafe.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <fstream>
#include "Logger.h"

Logger::Logger()
    : logFilePath_(L"AzureFilesSmbAuthLog.log"), verbosityLevel_(NONE), loggerInitialized_(false)
{ }

void Logger::Initialize()
{
    if (!loggerInitialized_)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!loggerInitialized_)
        {
            // Initialize verbosity level from the registry
            loadVerbosityFromRegistry(L"SOFTWARE\\Microsoft\\Windows Azure\\Storage\\Files\\SmbAuth");

            if (verbosityLevel_ != NONE)
            {
                // Open the log file
                logFile_.open(logFilePath_, std::ios::out | std::ios::app);
                if (!logFile_.is_open())
                {
                    ensureLogFileExists();
                    logFile_.open(logFilePath_, std::ios::out | std::ios::app);
                    if (!logFile_.is_open())
                    {
                        throw std::runtime_error("Failed to open log file.");
                    }
                }
            }
            loggerInitialized_ = true;
        }
    }
}

Logger::~Logger()
{
    if (loggerInitialized_)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (loggerInitialized_)
        {
            if (verbosityLevel_ != NONE)
            {
                if (logFile_.is_open())
                {
                    logFile_.close();
                }
            }
            loggerInitialized_ = false;
        }
    }
}

void Logger::log(_In_ PCWSTR   pwszFunction,
                 _In_ DWORD    dwLine,
                 _In_ LogLevel level,
                 _In_ PCWSTR   pszFormat, ...)
{
    if (level <= verbosityLevel_) 
    {
        std::lock_guard<std::mutex> lock(mutex_);

        va_list args;
        va_start(args, pszFormat);

        wchar_t szMessage[2048];
        HRESULT hr = StringCchVPrintfW(szMessage, ARRAYSIZE(szMessage), pszFormat, args);
        if (FAILED(hr)) throw hr;

        va_end(args);
        logFile_ << getTimestamp() << L" [" << logLevelToString(level) << L"] " << pwszFunction << L"(" << dwLine << L") " << szMessage << std::endl;
    }
}

void Logger::log(_In_ PCSTR pszFunction,
                 _In_ DWORD dwLine,
                 _In_ LogLevel level,
                 _In_ PCSTR pszFormat, ...)
{
    if (level <= verbosityLevel_) 
    {
        std::lock_guard<std::mutex> lock(mutex_);

        va_list args;
        va_start(args, pszFormat);

        char szMessage[2048];
        HRESULT hr = StringCchVPrintfA(szMessage, ARRAYSIZE(szMessage), pszFormat, args);
        if (FAILED(hr)) throw hr;

        va_end(args);

        logFile_ << getTimestamp() << " [" << logLevelToString(level) << "] " << pszFunction << "(" << dwLine << ") " << szMessage << std::endl;
    }
}

void Logger::ensureLogFileExists() 
{
    HANDLE hFile = CreateFileW( logFilePath_.c_str(),           // File name
                                GENERIC_READ | GENERIC_WRITE,   // Desired access
                                0,                              // Share mode (no sharing)
                                nullptr,                        // Security attributes
                                OPEN_ALWAYS,                    // Open if exists, create if not
                                FILE_ATTRIBUTE_NORMAL,          // Normal file attributes
                                nullptr                         // No template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD errorCode = GetLastError();
        throw std::runtime_error("Failed to create or open log file. Error code: " + std::to_string(errorCode));
    }

    CloseHandle(hFile); // Close the handle once the file is ensured to exist
}

void Logger::loadVerbosityFromRegistry(
    _In_ const std::wstring& registryKeyPath) 
{
    HKEY hKey;
    DWORD verbosity = 0; // Default to NONE

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryKeyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD dataSize = sizeof(DWORD);
        RegQueryValueExW(hKey, L"Verbosity", nullptr, nullptr, reinterpret_cast<LPBYTE>(&verbosity), &dataSize);
        RegCloseKey(hKey);
    }

    verbosityLevel_ = verbosityToLogLevel(verbosity);
}

std::wstring Logger::getTimestamp()
{
    SYSTEMTIME time;
    GetLocalTime(&time);

    wchar_t buffer[32];
    swprintf(buffer,
             sizeof(buffer) / sizeof(buffer[0]),
             L"%04d-%02d-%02d %02d:%02d:%02d",
             time.wYear, time.wMonth, time.wDay,
             time.wHour, time.wMinute, time.wSecond
             );

    return std::wstring(buffer);
}

Logger::LogLevel Logger::verbosityToLogLevel(
    _In_ DWORD verbosity)
{
    if (verbosity == 1) return LogLevel::ERR;
    if (verbosity == 2) return LogLevel::WARNING;
    if (verbosity == 3) return LogLevel::INFO;
    if (verbosity == 4) return LogLevel::VERBOSE;
    return LogLevel::NONE;
}

std::wstring Logger::logLevelToString(
    _In_ Logger::LogLevel level)
{
    switch (level) 
    {
        case LogLevel::ERR:     return L"ERROR";
        case LogLevel::WARNING: return L"WARN";
        case LogLevel::INFO:    return L"INFO";
        case LogLevel::VERBOSE: return L"VERB";
        default:                return L"NONE";
    }
}