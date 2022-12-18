#include "Includes.h"

int main()
{
    std::thread titleLoopT(Helper::titleLoop);
    Helper::titleLoopBool = true;

    // Checks::checkWindowsDefender();
    // Checks::check3rdPartyAntiVirus();
    Checks::checkSecureBoot();
    // Checks::checkCPUV();
    // Checks::uninstallRiotVanguard();
    Checks::installVCRedist();
    Checks::isChromeInstalled();
    Checks::disableChromeProtection();
    Checks::syncWindowsTime();

    Helper::titleLoopBool = false;
    titleLoopT.join();
    system("title Checking completed! APPLECHEATS.CC");
    Sleep(1500);
    //system("start https://applecheats.cc/");
    system("pause");
}