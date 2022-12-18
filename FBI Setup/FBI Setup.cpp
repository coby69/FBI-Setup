#include "Includes.h"

int main()
{
    // Begin the console title loop
    std::thread titleLoopT(Helper::titleLoop);
    Helper::titleLoopBool = true;

    // Add a message informing the user of how long it will take
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Please wait 1-2 minutes while we run through and check everything\n";
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";

    // Run through all the checks
    Checks::checkWindowsDefender();
    Checks::check3rdPartyAntiVirus();
    Checks::checkSecureBoot();
    Checks::checkCPUV();
    Checks::uninstallRiotVanguard();
    Checks::installVCRedist();
    Checks::isChromeInstalled();
    Checks::disableChromeProtection();
    Checks::syncWindowsTime();

    // Finish up everything
    SetConsoleTitleA("Checking completed!");
    system("start https://applecheats.cc/");
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Successfully checked everything, press anykey to close the program\n";
    Helper::titleLoopBool = false;
    titleLoopT.join();

    // Pause the program with no echo
    Helper::runSystemCommand("pause");

    // Exit the program
    return 1;
}