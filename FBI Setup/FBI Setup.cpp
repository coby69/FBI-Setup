// Made by Coby, all credits to me as I was the only one who contributed to it.
// This version was made on 27/12/2022 (DD/MM/YYYY).
// This is an open-source project and any and all code can be modified and change at any point in time.
// (thanks Kali for the read DWORD function)

#include "Includes.h"

int main()
{
    // Run the console settings setup
    Helper::setupConsole();

    // Begin the console title loop
    std::thread titleLoopT(Helper::titleLoop);
    Helper::titleLoopBool = true;

    // Add a message informing the user of how long it will take
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Please wait 1-2 minutes while we run through and check everything\n";
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";

    // Small sleep function so the user doesn't feel overwhelmed when first opening the program
    Sleep(1500);
    
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

    // Add a message informing the user we are running additional checks
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Successfully ran standard checks, now running additional checks\n";
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";

    // Run additional checks
    Checks::checkWinver();
    Checks::deleteSymbols();
    Checks::checkFastBoot();
    Checks::checkExploitProtection();
    Checks::checkSmartScreen();
    Checks::checkGameBar();

    // Seperate and notify user of additional checks
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Successfully ran additional checks, feel free to close the application\n";
    Color::setForegroundColor(Color::Green);
    std::cout << "Please take a screenshot of the program now and send it support";
    if (Helper::restartRequired)
    {
        Color::setForegroundColor(Color::Red);
        std::cout << "\n(Restart required to apply all changes)";
    }

    Helper::titleLoopBool = false;
    Sleep(300);
    titleLoopT.join();

    // While loop to hand the application
    while (true)
    {
        // Hang the application
        SetConsoleTitleA("Checking completed!");
    }

    // Exit the program
    return 1;
}