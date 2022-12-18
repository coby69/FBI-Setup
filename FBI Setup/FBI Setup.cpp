#include "Includes.h"

int main()
{
    std::thread titleLoopT(Helper::titleLoop);
    Helper::titleLoopBool = true;

    Checks::isChromeInstalled();
    Checks::disableChromeProtection();
    Checks::checkSecureBoot();
    Checks::syncWindowsTime();

    // TODO:
    // Checks::check3rdPartyAntiVirus();
    // Checks::uninstallRiotVanguard();
    // Checks::installVCRedist();
    // Checks::checkCPUV();

    Helper::titleLoopBool = false;
    titleLoopT.join();
    system("title Checking completed! APPLECHEATS.CC");
    system("start https://applecheats.cc/");
    system("pause");
}