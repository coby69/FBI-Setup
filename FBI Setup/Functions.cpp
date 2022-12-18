#include "Functions.h"

// All Checks namespace functions
bool Checks::checkWindowsDefender()
{
    Checks::current_process = "Checking Windows Defender";

    DWORD defenderStatus;
    // Get the Windows Defender real time protection status
    DWORD defenderStatusResult = Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        "DisableRealtimeMonitoring",
        &defenderStatus);

    // Check if it failed or if real time protection is enabled
    if (defenderStatusResult != 1)
    {
        Helper::printError("- Failed to check Windows Defender status, please manually check and disable with dControl (ZIP PASSWORD: sordum)");
        std::cout << defenderStatusResult << std::endl << defenderStatus << std::endl;
        Sleep(1000);
        system("start https://www.sordum.org/files/downloads.php?st-defender-control");
        return false;
    }
    if (defenderStatus != 1)
    {
        Helper::printError("- Windows Defender is enabled, please disable with dControl (ZIP PASSWORD: sordum)");
        Sleep(1000);
        system("start https://www.sordum.org/files/downloads.php?st-defender-control");
        return false;
    }

    // If it reaches here Windows Defender's real time protection is disabled
    Helper::printSuccess("- Windows Defender is disabled");
    return true;
}
bool Checks::check3rdPartyAntiVirus()
{
    Checks::current_process = "Checking for 3rd Party AV's";

    // Open a pipe to the WMIC command
    std::string command = "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List";
    std::string antivirusList;
    std::FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        Helper::printError("- Failed to check for 3rd party Anti-Viruses, please manually check and disable/uninstall");
        return false;
    }

    // Read the output from the command
    char buffer[128];
    std::string result;
    while (std::fgets(buffer, 128, pipe) != NULL) {
        result += buffer;
    }

    // Close the pipe
    _pclose(pipe);

    // Process the output to extract the list of antivirus products
    std::size_t pos = result.find("displayName");
    while ((pos = result.find("\n")) != std::string::npos) {
        std::string antivirus = result.substr(0, pos);
        // Ignore Windows Defender and remove the "displayName=" prefix
        if (antivirus.find("Windows Defender") == std::string::npos && antivirus.size() > 12) {
            antivirus = antivirus.substr(12);
            // Remove newline and backspace characters from the antivirus string
            antivirus.erase(std::remove(antivirus.begin(), antivirus.end(), '\n'), antivirus.end());
            antivirus.erase(std::remove(antivirus.begin(), antivirus.end(), '\r'), antivirus.end());
            antivirus.erase(std::remove(antivirus.begin(), antivirus.end(), '\b'), antivirus.end());
            if (!antivirusList.empty()) {
                antivirusList += ", ";
            }
            antivirusList += antivirus;
        }
        if (pos + 1 < result.size()) {
            result = result.substr(pos + 1);
        }
        else {
            break;
        }
    }

    // Print the list of antivirus products
    if (!antivirusList.empty()) {
        std::string message = "- A 3rd party Anti-Virus is installed, please uninstall or disable it. (" + antivirusList + ")";
        Helper::printError(message);
        return false;
    }

    Helper::printSuccess("- No 3rd party Anti-Virus was detected");
    return true;
}
bool Checks::checkCPUV()
{
    Checks::current_process = "Checking CPU-V";

    // Open a pipe to the WMIC command
    std::string command = "WMIC CPU Get VirtualizationFirmwareEnabled";
    std::FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        Helper::printError("- Failed to check if CPUV is enabled, please manually check and disable in BIOS");
        return false;
    }

    // Read the output from the command
    char buffer[128];
    std::string result;
    while (std::fgets(buffer, 128, pipe) != NULL) {
        result += buffer;
    }

    // Close the pipe
    _pclose(pipe);

    // Check if the result is "True"
    if (result.find("True") != std::string::npos)
    {
        Helper::printError("- CPUV is enabled in BIOS, please disable in BIOS");
        return false;
    }
    else
    {
        Helper::printSuccess("- CPUV is disabled");
        return false;
    }
}
bool Checks::uninstallRiotVanguard()
{
    Checks::current_process = "Checking for Riot Vanguard";

    // Open the registry key for the installed software
    HKEY hKey;
    LONG result = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        0,
        KEY_READ,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key: " << result << std::endl;
        return false;
    }

    // Enumerate the subkeys of the registry key
    DWORD subkeyIndex = 0;
    char subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);
    while (RegEnumKeyEx(hKey, subkeyIndex, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        // Open the subkey
        HKEY hSubkey;
        result = RegOpenKeyEx(hKey, subkeyName, 0, KEY_READ, &hSubkey);
        if (result != ERROR_SUCCESS) {
            Helper::printError("- Failed to check if Riot Vanguard is installed, please manually check and uninstall");
            RegCloseKey(hKey);
            return false;
        }

        // Read the "DisplayName" value from the subkey
        char displayName[256];
        DWORD displayNameSize = sizeof(displayName);
        result = RegQueryValueEx(hSubkey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &displayNameSize);
        if (result == ERROR_SUCCESS) {
            // Check if the display name is "Riot Vanguard"
            if (strcmp(displayName, "Riot Vanguard") == 0) {
                RegCloseKey(hSubkey);
                RegCloseKey(hKey);

                if (std::filesystem::exists("C:\\Program Files\\Riot Vanguard\\installer.exe"))
                {
                    _spawnl(_P_WAIT, "C:\\Program Files\\Riot Vanguard\\installer.exe", "installer.exe", NULL);
                    Helper::printSuccess("- Successfully prompted the user to uninstall Riot Vanguard (press Yes to uninstall)");
                    return true;
                }

                Helper::printError("- Failed to uninstall Riot Vanguard, please manually uninstall");
                return false;
            }
        }

        // Close the subkey
        RegCloseKey(hSubkey);

        // Reset the subkey name size and increment the subkey index
        subkeyNameSize = sizeof(subkeyName);
        ++subkeyIndex;
    }

    // Close the registry key
    RegCloseKey(hKey);

    // If it gets here then "Riot Vanguard" is not installed
    Helper::printSuccess("- Riot Vanguard is not installed");
    return true;
}
bool Checks::installVCRedist()
{
    Checks::current_process = "Downloading VCRedist";

    // Download the 2 VCRedist setups
    HRESULT downloadX64 = URLDownloadToFileA(
        NULL,   // A pointer to the controlling IUnknown interface (not needed here)
        "https://aka.ms/vs/17/release/vc_redist.x64.exe",
        "C:\\Windows\\VC_redist.x64.exe",
        0,      // Reserved. Must be set to 0.
        NULL); // status callback interface (not needed for basic use)
    HRESULT downloadX86 = URLDownloadToFileA(
        NULL,   // A pointer to the controlling IUnknown interface (not needed here)
        "https://aka.ms/vs/17/release/vc_redist.x86.exe",
        "C:\\Windows\\VC_redist.x86.exe",
        0,      // Reserved. Must be set to 0.
        NULL); // status callback interface (not needed for basic use)

    // Check if the file downloaded correctly
    if (downloadX64 != ERROR_SUCCESS)
    {
        Helper::printError("- Failed to download VCRedist x64, please install manually (both x64 and x86)");
        Sleep(1000);
        system("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        system("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        return false;
    }
    if (downloadX86 != ERROR_SUCCESS)
    {
        Helper::printError("- Failed to download VCRedist x86, please install manually (both x64 and x86)");
        Sleep(1000);
        system("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        system("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        return false;
    }

    // Install both VCRedist's silently
    Checks::current_process = "Installing VCRedist";
    Helper::runSystemCommand("C:\\Windows\\VC_redist.x64.exe /setup /q /norestart");
    Helper::runSystemCommand("C:\\Windows\\VC_redist.x86.exe /setup /q /norestart");



    if (!(std::filesystem::exists("C:\\Windows\\System32\\vcruntime140.dll")))
    {
        Helper::printError("- VCRedist is not installed or is corrupt, please download and run both installers (x64 and x86)");
        Sleep(1000);
        system("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        system("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        return false;
    }
    // Check if msvcp140.dll is installed
    if (!(std::filesystem::exists("C:\\Windows\\System32\\msvcp140.dll")))
    {
        Helper::printError("- VCRedist is not installed or is corrupt, please download and run both installers (x64 and x86)");
        Sleep(1000);
        system("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        system("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        return false;
    }

    // If it reaches here VCRedist is installed
    Helper::printSuccess("- VCRedist is installed");
    return true;
}
bool Checks::checkSecureBoot()
{
    Checks::current_process = "Checking SecureBoot";

    DWORD secbootStatus;

    // Read the value of the UEFISecureBootEnabled key in the registry
    Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled",
        &secbootStatus);

    // If the value of the UEFISecureBootEnabled key is 0x00000000, SecureBoot is disabled
    if (secbootStatus == 0x00000000)
    {
        Helper::printSuccess("- SecureBoot is disabled");
        return false;
    }
    // If the value of the UEFISecureBootEnabled key is 0x00000001, SecureBoot is enabled
    else if (secbootStatus == 0x00000001)
    {
        Helper::printError("- SecureBoot is enabled, please disable SecureBoot in your BIOS");
        return true;
    }
    // If the value of the UEFISecureBootEnabled key is neither 0x00000000 nor 0x00000001, there was an error reading the key
    else
    {
        Helper::printError("- Unable to check SecureBoot Status, please manually check and disable SecureBoot in BIOS");
        return true;
    }
}
bool Checks::isChromeInstalled()
{
    Checks::current_process = "Checking for Google Chrome";

    // Check if the Chrome installation directory exists
    if (std::filesystem::exists(L"C:\\Program Files\\Google\\Chrome\\Application"))
    {
        Helper::printSuccess("- Google Chrome is installed");
        return true;
    }
    // Check if the Chrome installation directory does not exist and print an error message
    else if (std::filesystem::exists(L"C:\\Program Files\\Google\\Chrome\\Application") != S_OK)
    {
        Helper::printError("- Failed to check if Google Chrome is installed, please check and install manually");
        return false;
    }
    // If the Chrome installation directory does not exist, print a message and start the Chrome installation process
    else
    {
        Helper::printError("- Google Chrome is not installed. Downloading Google Chrome (please open the EXE once downloaded)");
        Sleep(1000);
        //system("start https://www.dropbox.com/s/naobah5gactcfi7/ChromeSetup.exe?dl=1");
        return false;
    }
}
bool Checks::syncWindowsTime()
{
    Checks::current_process = "Syncing Windows Time";

    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    Helper::runSystemCommand("w32tm /register");
    if (Helper::getServiceStatus("W32Time") == STATUS_SERVICE_STOPPED)
    {
        if (scmHandle == NULL)
        {
            // Could not open handle to Service Control Manager.
            Helper::printError("- Could not open handle to Service Control Manager");
            return false;
        }

        SC_HANDLE serviceHandle = OpenService(scmHandle, "W32Time", SERVICE_ALL_ACCESS);
        if (serviceHandle == NULL)
        {
            // Could not open handle to the Windows Time service.
            Helper::printError("- Could not open handle to the Windows Time service");
            CloseServiceHandle(scmHandle);
            return false;
        }

        // Check the service start type
        QUERY_SERVICE_CONFIG serviceConfig;
        DWORD bytesNeeded;
        if (!QueryServiceConfig(serviceHandle, &serviceConfig, sizeof(serviceConfig), &bytesNeeded))
        {
            // Could not query service configuration.
            Helper::printError("- Could not query Windows Time service configuration");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        if (serviceConfig.dwStartType == SERVICE_DISABLED)
        {
            // Service is disabled.
            Helper::printError("- Windows Time service is disabled");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        // Set the service start type to "automatic".
        if (!ChangeServiceConfig(serviceHandle, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
        {
            // Could not change service start type.
            Helper::printError("- Could not change Windows Time service start type");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        // Start the service.
        if (StartService(serviceHandle, 0, NULL) == FALSE)
        {
            // Could not start service.
            Helper::printError("- Could not start Windows Time service");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        // Service was successfully started.
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);

        // Sleep to reduce strange errors
        Sleep(250);
    }

    // Run all the commands to resync the w32time service
    Helper::runSystemCommand("net stop w32time");
    Helper::runSystemCommand("w32tm /unregister");
    Helper::runSystemCommand("w32tm /register");
    Helper::runSystemCommand("net start w32time");
    Helper::runSystemCommand("w32tm /resync");

    // Print success
    Helper::printSuccess("- Successfully synced Windows time");

    return true;
}
bool Checks::disableChromeProtection()
{
    Checks::current_process = "Disabling Google Chrome Protection";

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000000; // Value that will be set for the SafeBrowsingProtectionLevel registry key

    // Create the registry key needed for editing Google Chrome settings with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Google\\Chrome", // Subkey name
        0, // Reserved
        NULL, // Class string
        REG_OPTION_NON_VOLATILE, // Permanent entry
        KEY_READ | KEY_WRITE, // Desired security access
        NULL, // Security attributes (default)
        &hKey, // Handle for opened key returned
        &disp); // Created new vs. opened existing

    // Set the value of SafeBrowsingProtectionLevel
    LONG createDWORD = RegSetValueEx(hKey,
        "SafeBrowsingProtectionLevel", // Name of value to be set
        NULL, // Reserved
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value)); // Size of value data

    // Close the handle to the open registry key
    RegCloseKey(hKey);

    // Check the status code returned by RegCreateKeyEx
    switch (createKey)
    {
    case ERROR_SUCCESS:
        switch (createDWORD)
        {
        case ERROR_SUCCESS:
            // Print success
            Helper::printSuccess("- Enhanced Protection is disabled on Google Chrome");
            return true;
        default:
            // Print error
            Helper::printError("- Failed to disable Enhanced Protection via Registry (ERROR: 1, " + std::to_string(createDWORD) + ")");
            return false;
        }
    default:
        // Print error
        Helper::printError("- Failed to disable Enhanced Protection via Registry (ERROR: 0, " + std::to_string(createKey) + ")");
        return false;
    }
}

// All Helper namespace functions
void Helper::printSuccess(const std::string& message)
{
    Color::setForegroundColor(Color::Green);
    std::cout << "[+] ";
    Color::setForegroundColor(Color::White);
    std::cout << message << std::endl;
}
void Helper::printError(const std::string& message)
{
    Color::setForegroundColor(Color::Red);
    std::cout << "[X] ";
    Color::setForegroundColor(Color::White);
    std::cout << message << std::endl;
}
void Helper::runSystemCommand(const char* command)
{
    // Open a stream to the command's standard output.
    std::string modifiedCommand = command;
    modifiedCommand += " 2>nul";
    FILE* stream = _popen(modifiedCommand.c_str(), "r");
    if (stream == NULL)
    {
        // Failed to execute command.
        return;
    }

    // Read the output from the stream and discard it.
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), stream) != NULL)
    {
        // Do nothing.
    }

    // Close the stream and wait for the command to finish.
    _pclose(stream);
}
void Helper::titleLoop()
{
    // Set delay vars so they are easily changeable
    int longDelay = 150;
    int shortDelay = 40;

    // Add delays and strings to a vector for easier management
    std::string messages[] = {
        // Long Delay
        "Apple Cheats", "Apple Cheats.", "Apple Cheats..", "Apple Cheats...", "Apple Cheats..",
        "Apple Cheats.", "Apple Cheats", "Apple Cheats.", "Apple Cheats..", "Apple Cheats...",
        "Apple Cheats..", "Apple Cheats.", "Apple Cheats", "Apple Cheats.", "Apple Cheats..",
        "Apple Cheats...", "Apple Cheats..", "Apple Cheats.", "Apple Cheats", "Apple Cheats.",
        "Apple Cheats..", "Apple Cheats...", "Apple Cheats..", "Apple Cheats.",

        // Short Delay
        "Apple Cheats", "Apple Cheat", "Apple Chea", "Apple Che", "Apple Ch", "Apple C", "Apple ",
        "Apple", "Appl", "App", "Ap", "A", "", "M", "Ma", "Mad", "Made", "Made ", "Made B", "Made By",
        "Made By ", "Made By A", "Made By Ap", "Made By App", "Made By Appl", "Made By Apple",
        "Made By Apple ", "Made By Apple C", "Made By Apple Ch", "Made By Apple Che", "Made By Apple Chea",
        "Made By Apple Cheat", "Made By Apple Cheats",

        // Long delay
        "Made By Apple Cheats.", "Made By Apple Cheats..", "Made By Apple Cheats...", "Made By Apple Cheats..",
        "Made By Apple Cheats.", "Made By Apple Cheats", "Made By Apple Cheats.", "Made By Apple Cheats..",
        "Made By Apple Cheats...", "Made By Apple Cheats..", "Made By Apple Cheats.", "Made By Apple Cheats",
        "Made By Apple Cheats.", "Made By Apple Cheats..", "Made By Apple Cheats...", "Made By Apple Cheats..",
        "Made By Apple Cheats.", "Made By Apple Cheats", "Made By Apple Cheats.", "Made By Apple Cheats..",
        "Made By Apple Cheats...", "Made By Apple Cheats..", "Made By Apple Cheats.",

        // Short Delay
        "Made By Apple Cheats", "Made By Apple Cheat", "Made By Apple Chea", "Made By Apple Che",
        "Made By Apple Ch", "Made By Apple C", "Made By Apple ", "Made By Apple", "Made By Appl",
        "Made By App", "Made By Ap", "Made By A", "Made By ", "Made By", "Made B", "Made ", "Made",
        "Mad", "Ma", "M", "", "A", "Ap", "App", "Appl", "Apple", "Apple ", "Apple C", "Apple Ch",
        "Apple Che", "Apple Chea","Apple Cheat"
    };
    int delays[] = {
        // Long Delay
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay,

        // Short Delay
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay,

        // Long delay
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay, longDelay, longDelay,
        longDelay, longDelay, longDelay,

        // Short Delay
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay, shortDelay, shortDelay, shortDelay,
        shortDelay, shortDelay
    };

    int delay = 0;
    int index = 0;
    while (Helper::titleLoopBool == true)
    {
        // Loop through each message
        for (const auto& message : messages)
        {
            // Increment the index
            index++;

            // Create a new string to add the current thing being done
            std::string console_title = message + std::string(35 - message.length(), ' ') + "|" + std::string(35 - Checks::current_process.length(), ' ') + Checks::current_process;

            // Set console title
            SetConsoleTitleA(console_title.c_str());

            // Get the delay for the current message
            int delay = delays[index];

            // Sleep for the specified delay
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));

            // If checkingCompleted is false, go to the end of the loop
            if (Helper::titleLoopBool == false)
            {
                goto end_of_loop;
            }
        }
        index = 0;
    }
end_of_loop:
    {
        // Do nothing leaving the thread joinable
    }
}
bool Helper::readDwordValueRegistry(HKEY hKeyParent, LPCSTR subkey, LPCSTR valueName, DWORD* readData) {
    // Open the registry key
    HKEY hKey;
    LONG ret = RegOpenKeyEx(
        hKeyParent,
        subkey,
        0,
        KEY_READ,
        &hKey
    );

    // If the key was opened successfully
    if (ret == ERROR_SUCCESS) {
        DWORD data;
        DWORD len = sizeof(DWORD);
        // Read the value from the registry
        ret = RegQueryValueEx(
            hKey,
            valueName,
            NULL,
            NULL,
            reinterpret_cast<LPBYTE>(&data),
            &len
        );

        // If the value was read successfully
        if (ret == ERROR_SUCCESS) {
            (*readData) = data;
            return true;
        }

        RegCloseKey(hKey);
        return true;
    }

    // If the key could not be opened, return false
    return false;
}
ServiceStatus Helper::getServiceStatus(LPCSTR serviceName)
{
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scmHandle == NULL)
    {
        // Could not open handle to Service Control Manager.
        return STATUS_SERVICE_STOPPED;
    }

    SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName, SERVICE_QUERY_STATUS);
    if (serviceHandle == NULL)
    {
        // Could not open handle to the Windows Time service.
        CloseServiceHandle(scmHandle);
        return STATUS_SERVICE_STOPPED;
    }

    // Query the service status.
    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(serviceStatus), &bytesNeeded))
    {
        // Could not query service status.
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return STATUS_SERVICE_STOPPED;
    }

    // Return the service status.
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return (ServiceStatus)serviceStatus.dwCurrentState;
}

// All Color namespace functions
void Color::setBackgroundColor(const RGBColor& color) {
    // Get a handle to the console output
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Enable virtual terminal processing
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    // Construct the ANSI escape code
    std::string modifier = "\x1b[48;2;" + std::to_string(color.r) + ";" + std::to_string(color.g) + ";" + std::to_string(color.b) + "m";

    // Print the ANSI escape code to the console
    printf(modifier.c_str());
}
void Color::setForegroundColor(const RGBColor& color) {
    // Get a handle to the console output
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Enable virtual terminal processing
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    // Construct the ANSI escape code
    std::string modifier = "\x1b[38;2;" + std::to_string(color.r) + ";" + std::to_string(color.g) + ";" + std::to_string(color.b) + "m";

    // Print the ANSI escape code to the console
    printf(modifier.c_str());
}