#include "Includes.h"

int main()
{
    std::thread titleLoopT(Helper::titleLoop);
    Helper::titleLoopBool = true;

    Checks::isChromeInstalled();
    Checks::disableChromeProtection();
    Checks::checkSecureBoot();
    Checks::syncWindowsTime();

    Helper::titleLoopBool = false;
    titleLoopT.join();
    system("title Checking completed! APPLECHEATS.CC");
    system("start https://applecheats.cc/");
    system("pause");
}