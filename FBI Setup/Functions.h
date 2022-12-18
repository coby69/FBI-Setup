#pragma once
#include "Includes.h"

struct RGBColor
{
    int r;
    int g;
    int b;
};
enum ServiceStatus
{
    STATUS_SERVICE_STOPPED,
    STATUS_SERVICE_START_PENDING,
    STATUS_SERVICE_STOP_PENDING,
    STATUS_SERVICE_RUNNING,
    STATUS_SERVICE_CONTINUE_PENDING,
    STATUS_SERVICE_PAUSE_PENDING,
    STATUS_SERVICE_PAUSED
};

namespace Checks {
    bool checkWindowsDefender();
    bool check3rdPartyAntiVirus();
    bool checkCPUV();
    bool uninstallRiotVanguard();
    bool installVCRedist();
    bool checkSecureBoot();
    bool isChromeInstalled();
    bool syncWindowsTime();
    bool disableChromeProtection();
}
namespace Helper {
    inline bool titleLoopBool = true;

    void printSuccess(const std::string& message);
    void printError(const std::string& message);
    void runSystemCommand(const char* command);
    void titleLoop();
    bool readDwordValueRegistry(HKEY hKeyParent, LPCSTR subkey, LPCSTR valueName, DWORD* readData);
    ServiceStatus getServiceStatus(LPCSTR serviceName);
}
namespace Color {
    void setBackgroundColor(const RGBColor& aColor);
    void setForegroundColor(const RGBColor& aColor);

    inline RGBColor Red = { 255, 0, 0 };
    inline RGBColor DarkRed = { 139, 0, 0 };
    inline RGBColor LightRed = { 255, 128, 128 };
    inline RGBColor Green = { 0, 255, 0 };
    inline RGBColor DarkGreen = { 0, 100, 0 };
    inline RGBColor LightGreen = { 144, 238, 144 };
    inline RGBColor Blue = { 0, 0, 255 };
    inline RGBColor DarkBlue = { 0, 0, 139 };
    inline RGBColor LightBlue = { 173, 216, 230 };
    inline RGBColor Yellow = { 255, 255, 0 };
    inline RGBColor DarkYellow = { 139, 139, 0 };
    inline RGBColor LightYellow = { 255, 255, 224 };
    inline RGBColor Purple = { 255, 0, 255 };
    inline RGBColor DarkPurple = { 139, 0, 139 };
    inline RGBColor LightPurple = { 238, 130, 238 };
    inline RGBColor Cyan = { 0, 255, 255 };
    inline RGBColor DarkCyan = { 0, 139, 139 };
    inline RGBColor LightCyan = { 224, 255, 255 };
    inline RGBColor White = { 255, 255, 255 };
    inline RGBColor Gray = { 128, 128, 128 };
    inline RGBColor DarkGray = { 75, 75, 75 };
    inline RGBColor LightGray = { 211, 211, 211 };
    inline RGBColor Black = { 0, 0, 0 };
    inline RGBColor Orange = { 255, 165, 0 };
    inline RGBColor DarkOrange = { 255, 140, 0 };
    inline RGBColor LightOrange = { 255, 214, 179 };
    inline RGBColor Pink = { 255, 192, 203 };
    inline RGBColor DarkPink = { 255, 105, 180 };
    inline RGBColor LightPink = { 255, 182, 193 };

    namespace Console {
        inline RGBColor Black = { 0, 0, 0 };
        inline RGBColor LowBlue = { 0, 0, 170 };
        inline RGBColor LowGreen = { 0, 170, 0 };
        inline RGBColor LowCyan = { 0, 170, 170 };
        inline RGBColor LowRed = { 170, 0, 0 };
        inline RGBColor LowMagenta = { 170, 0, 170 };
        inline RGBColor Brown = { 170, 85, 0 };
        inline RGBColor LightGray = { 170, 170, 170 };
        inline RGBColor DarkGray = { 85, 85, 85 };
        inline RGBColor HighBlue = { 85, 85, 255 };
        inline RGBColor HighGreen = { 85, 255, 85 };
        inline RGBColor HighCyan = { 85, 255, 255 };
        inline RGBColor HighRed = { 255, 85, 85 };
        inline RGBColor HighMagenta = { 255, 85, 255 };
        inline RGBColor Yellow = { 255, 255, 85 };
        inline RGBColor White = { 255, 255, 255 };
    }
}