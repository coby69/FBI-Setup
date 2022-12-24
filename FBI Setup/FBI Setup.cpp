// Made by Coby, all credits to me as I was the only one who contributed to it.
// This version was made on 24/12/2022 (DD/MM/YYYY).
// This is a BETA version and is not fully complete hence
// many things are subject to change.

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

    // Finish up everything
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Successfully ran standard checks";

    Checks::current_process = "Waiting for user input";

    MessageBeep(MB_ICONWARNING);
    if (MessageBoxA(NULL, "Would you like to run additional checks?", "FBI Setup", MB_ICONQUESTION | MB_YESNO) == IDNO)
    {
        std::cout << ", feel free to close the application";

        Helper::titleLoopBool = false;
        titleLoopT.join();

        SetConsoleTitleA("Checking completed!");

        // While loop to hand the application
        while (true)
        {
            // Hang the application
        }

        // Exit the program
        return 1;
    }
    
    // Add a message informing the user of how long it will take
    Color::setForegroundColor(Color::Cyan);
    std::cout << ", now running additional checks\n";
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";

    // Run additional checks
    Checks::checkWinver();
    Checks::deleteSymbols();
    Checks::checkFastBoot();

    // Seperate and notify user of additional checks
    Color::setForegroundColor(Color::LightGray);
    std::cout << "-----------------------------------------------------------------\n";
    Color::setForegroundColor(Color::Cyan);
    std::cout << "Successfully ran additional checks, feel free to close the application";

    Helper::titleLoopBool = false;
    titleLoopT.join();

    SetConsoleTitleA("Checking completed!");

    // While loop to hand the application
    while (true)
    {
        // Hang the application
    }

    // Exit the program
    return 1;
}