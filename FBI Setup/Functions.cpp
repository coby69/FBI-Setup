#include "Functions.h"

// All Checks namespace functions
void Checks::checkWindowsDefender()
{
    SetConsoleTitleA("Checking Windows Defender");

    // Get the state of the Windows Defender service
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        Helper::printError("- Failed to check Windows Defender. Please manually check and disable Windows Defender (PASSWORD: sordum)");
        Sleep(1000);
        Helper::runSystemCommand("start https://www.sordum.org/files/downloads.php?st-defender-control");
        return;
    }
    SC_HANDLE service = OpenService(scm, "WinDefend", SERVICE_QUERY_STATUS);
    if (service == NULL) {
        Helper::printError("- Failed to check Windows Defender. Please manually check and disable Windows Defender (PASSWORD: sordum)");
        Sleep(1000);
        Helper::runSystemCommand("start https://www.sordum.org/files/downloads.php?st-defender-control");
        CloseServiceHandle(scm);
        return;
    }
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        Helper::printError("- Failed to check Windows Defender. Please manually check and disable Windows Defender (PASSWORD: sordum)");
        Sleep(1000);
        Helper::runSystemCommand("start https://www.sordum.org/files/downloads.php?st-defender-control");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return;
    }

    // Print the state of the Windows Defender service
    if (status.dwCurrentState == SERVICE_RUNNING) {
        Helper::printError("- Windows Defender is enabled, please disable with dControl (PASSWORD: sordum)");
        Sleep(1000);
        Helper::runSystemCommand("start https://www.sordum.org/files/downloads.php?st-defender-control");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return;
    }
    else {
        Helper::printSuccess("- Windows Defender is disabled", false);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return;
    }
}
void Checks::check3rdPartyAntiVirus()
{
    SetConsoleTitleA("Checking for 3rd Party Anti-Viruses");

    // Open a pipe to the WMIC command
    std::string command = "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List";
    std::string antivirusList;
    std::FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        Helper::printError("- Failed to check for 3rd party Anti-Viruses, please manually check and disable/uninstall");
        return;
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
        return;
    }

    Helper::printSuccess("- No 3rd party Anti-Virus was detected", false);
    return;
}
void Checks::checkCPUV()
{
    SetConsoleTitleA("Checking CPUV-V");

    // Open a pipe to the WMIC command
    std::string command = "WMIC CPU Get VirtualizationFirmwareEnabled";
    std::FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        Helper::printError("- Failed to check if CPUV is enabled, please manually check and disable in BIOS");
        return;
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
        return;
    }
    else
    {
        Helper::printSuccess("- CPUV is disabled", false);
        return;
    }
}
void Checks::uninstallRiotVanguard()
{
    SetConsoleTitleA("Checking for Riot Vanguard");

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
        Helper::printError("- Failed to open reg key. Please manually check and uninstall Riot Vanguard");
        return;
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
            return;
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
                    Helper::printSuccess("- Successfully prompted the user to uninstall Riot Vanguard (press Yes to uninstall)", true);
                    return;
                }

                Helper::printError("- Failed to uninstall Riot Vanguard, please manually uninstall");
                return;
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
    Helper::printSuccess("- Riot Vanguard is not installed", false);
    return;
}
void Checks::installVCRedist()
{
    SetConsoleTitleA("Downloading VCRedist");
    Helper::vcComplete = false;

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
        Helper::printError("- Failed to download VCRedist x64, please install manually (anti-virus enabled?)");
        Sleep(1000);
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        Helper::vcComplete = true;
        return;
    }
    if (downloadX86 != ERROR_SUCCESS)
    {
        Helper::printError("- Failed to download VCRedist x86, please install manually (anti-virus enabled?)");
        Sleep(1000);
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        Helper::vcComplete = true;
        return;
    }

    // Install both VCRedist's silently
    SetConsoleTitleA("Installing VCRedist");
    Helper::runSystemCommand("C:\\Windows\\VC_redist.x64.exe /setup /q /norestart");
    Helper::runSystemCommand("C:\\Windows\\VC_redist.x86.exe /setup /q /norestart");



    if (!(std::filesystem::exists("C:\\Windows\\System32\\vcruntime140.dll")))
    {
        Helper::printError("- VCRedist didn't install correctly or is corrupt, please download and run both installers (x64 and x86)");
        Sleep(1000);
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        Helper::vcComplete = true;
        return;
    }
    // Check if msvcp140.dll is installed
    if (!(std::filesystem::exists("C:\\Windows\\System32\\msvcp140.dll")))
    {
        Helper::printError("- VCRedist didn't install correctly or is corrupt, please download and run both installers (x64 and x86)");
        Sleep(1000);
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x64.exe");
        Helper::runSystemCommand("start https://aka.ms/vs/17/release/vc_redist.x86.exe");
        Helper::vcComplete = true;
        return;
    }

    // If it reaches here VCRedist is installed
    Helper::printSuccess("- VCRedist is installed", false);
    Helper::vcComplete = true;
    return;
}
void Checks::checkSecureBoot()
{
    SetConsoleTitleA("Checking Secure-Boot");

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
        Helper::printSuccess("- SecureBoot is disabled", false);
        return;
    }
    // If the value of the UEFISecureBootEnabled key is 0x00000001, SecureBoot is enabled
    else if (secbootStatus == 0x00000001)
    {
        Helper::printError("- SecureBoot is enabled, please disable SecureBoot in your BIOS");
        return;
    }
    // If the value of the UEFISecureBootEnabled key is neither 0x00000000 nor 0x00000001, there was an error reading the key
    else
    {
        Helper::printError("- Unable to check SecureBoot Status, please manually check and disable SecureBoot in BIOS");
        return;
    }
}
void Checks::isChromeInstalled()
{
    SetConsoleTitleA("Checking for Google Chrome");

    // Check if the Chrome installation directory exists
    if (std::filesystem::exists(L"C:\\Program Files\\Google\\Chrome\\Application"))
    {
        Helper::printSuccess("- Google Chrome is installed", false);
        return;
    }
    // Check if the Chrome installation directory does not exist and print an error message
    else if (std::filesystem::exists(L"C:\\Program Files\\Google\\Chrome\\Application") != S_OK)
    {
        Helper::printError("- Failed to check if Google Chrome is installed, please check and install manually");
        return;
    }
    // If the Chrome installation directory does not exist, print a message and start the Chrome installation process
    else
    {
        Helper::printError("- Google Chrome is not installed. Downloading Google Chrome (please open the EXE once downloaded)");
        Sleep(1000);
        Helper::runSystemCommand("start https://cdn.discordapp.com/attachments/1044581773960560660/1054138215822544956/ChromeSetup.exe");
        return;
    }
}
void Checks::syncWindowsTime()
{
    SetConsoleTitleA("Syncing Windows Time");

    // Open the Service Control Manager
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    // Register the w32tm service to fix some errors with the w32tm service
    Helper::runSystemCommand("w32tm /register");
    if (Helper::getServiceStatus("W32Time") == STATUS_SERVICE_STOPPED)
    {
        if (scmHandle == NULL)
        {
            // Could not open handle to Service Control Manager.
            Helper::printError("- Could not open handle to Service Control Manager");
            return;
        }

        SC_HANDLE serviceHandle = OpenService(scmHandle, "W32Time", SERVICE_ALL_ACCESS);
        if (serviceHandle == NULL)
        {
            // Could not open handle to the Windows Time service.
            Helper::printError("- Could not open handle to the Windows Time service");
            CloseServiceHandle(scmHandle);
            return;
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
            return;
        }

        if (serviceConfig.dwStartType == SERVICE_DISABLED)
        {
            // Service is disabled.
            Helper::printError("- Windows Time service is disabled");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return;
        }

        // Set the service start type to "automatic".
        if (!ChangeServiceConfig(serviceHandle, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
        {
            // Could not change service start type.
            Helper::printError("- Could not change Windows Time service start type");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return;
        }

        // Start the service.
        if (StartService(serviceHandle, 0, NULL) == FALSE)
        {
            // Could not start service.
            Helper::printError("- Could not start Windows Time service");
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return;
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
    Helper::printSuccess("- Successfully synced Windows time", false);
    return;
}
void Checks::disableChromeProtection()
{
    SetConsoleTitleA("Disabling Google Chrome Protection");

    DWORD safeBrowsingProtectionLevelStatus;

    // Read the value of the SafeBrowsingProtectionLevel registry key
    // This key determines the level of protection on Google Chrome
    if (Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Google\\Chrome", // Subkey name
        "SafeBrowsingProtectionLevel", // DWORD name
        &safeBrowsingProtectionLevelStatus) == true)
    {
        if (safeBrowsingProtectionLevelStatus == 0x00000001)
        {
            Helper::printSuccess("- Protection is disabled on Google Chrome is disabled", false);
            return;
        }
    }

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000001; // Value that will be set for the SafeBrowsingProtectionLevel registry key

    // Create the registry key needed for editing google chromes protection settings with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Google\\Chrome", // Subkey name
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &disp);

    // Set the value of SafeBrowsingProtectionLevel
    LONG createDWORD = RegSetValueEx(hKey,
        "SafeBrowsingProtectionLevel", // Name of value to be set
        NULL,
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value));

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
            Helper::printSuccess("- Successfully disabled protection on Google Chrome", true);
            return;
        default:
            // Print error
            Helper::printError("- Failed to disable protection on Google Chrome (Error: 1, " + std::to_string(createDWORD) + ")");
            return;
        }
    default:
        // Print error
        Helper::printError("- Failed to disable protection on Google Chrome (Error: 0, " + std::to_string(createKey) + ")");
        return;
    }
}

// Additional checks
void Checks::checkWinver()
{
    SetConsoleTitleA("Checking Winver");

    // Open a pipe to the WMIC command
    std::string command = "wmic os get version | findstr /R \"[0-9]\\.[0-9]\\.[0-9]\"";
    std::FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        Helper::printError("- Failed to check Winver, please check manually");
        return;
    }

    // Read the output from the command
    char buffer[128];
    std::string result;
    while (std::fgets(buffer, 128, pipe) != NULL) {
        result += buffer;
    }

    // Close the pipe
    _pclose(pipe);

    // Extract the build number from the result
    std::istringstream iss(result);
    int major, minor, build;
    char period;
    iss >> major >> period >> minor >> period >> build;

    // Define a map to use to compare the build to the winver
    std::map<int, std::string> build_map = {
        // Windows 10 builds
        {10240, "Windows 10 NT 10.0"},
        {10586, "Windows 10 1511"},
        {14393, "Windows 10 1607"},
        {15063, "Windows 10 1703"},
        {16299, "Windows 10 1709"},
        {17134, "Windows 10 1803"},
        {17763, "Windows 10 1809"},
        {18362, "Windows 10 1903"},
        {19041, "Windows 10 2004"},
        {19042, "Windows 10 20H2"},
        {19043, "Windows 10 21H1"},
        {19044, "Windows 10 21H2"},
        {19045, "Windows 10 22H2"},
        // Windows 11 builds
        {22000, "Windows 11 21H2"},
        {22621, "Windows 11 22H2"},
    };

    // Define the different builds that cause issues and the minimum build
    int min_build = 19041; // Minimum build number to support (2004 or 22H2)
    int trouble_win10_build = 19045; // Build that causes issues on win 10
    int trouble_win11_build = 22621; // Build that causes issues on win 11

    // Check the build to the corresponding string with the map
    auto it = build_map.find(build);
    if (it != build_map.end()) {
        std::string winver = it->second;

        // Check if winver is unsupported
        if (build < min_build)
        {
            Helper::printError("- Unsupported Winver: " + winver + ". Please downgrade");
            return;
        }

        // Check if winver is troublesome (win 10)
        if (build == trouble_win10_build)
        {
            Helper::printConcern("- Winver: \"" + winver + "\" is a 50/50, if error contact to support");
            return;
        }
        // Check if winver is troublesome (win 11)
        else if (build == trouble_win11_build)
        {
            Helper::printConcern("- Winver: \"" + winver + "\" is a 50/50, if error contact to support");
            return;
        }

        // If it got here, the winver should be fine
        Helper::printSuccess("- Winver is supported (" + winver + ")", false);
        return;
    }
    // If it got here, then the build doesnt match with any winvers
    else {
        Helper::printError("- Failed to check Winver, please check manually");
        return;
    }
}
void Checks::deleteSymbols()
{
    SetConsoleTitleA("Deleting C:\\Symbols");

    // Set the path of the directory to delete
    std::string path = "C:\\Symbols";

    // Check if the directory exists
    if (std::filesystem::exists(path))
    {
        // Try to delete the directory and all its contents
        if (!(std::filesystem::remove_all(path)))
        {
            // If the directory could not be deleted, print an error message
            Helper::printError("- Unable to delete " + path + ", please delete manually");
            return;
        }

        // If the directory was successfully deleted, print a success message
        Helper::printSuccess("- Successfully deleted " + path, true);
        return;
    }

    // If the directory does not exist, print a success message
    Helper::printSuccess("- " + path + " folder does not exsist", false);
    return;
}
void Checks::checkFastBoot()
{
    SetConsoleTitleA("Checking Fast-Boot");

    DWORD fastBootStatus;

    // Read the value of the HiberbootEnabled registry key
    // This key determines whether Fast Boot is enabled or disabled
    if (Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", // Subkey name
        "HiberbootEnabled", // DWORD name
        &fastBootStatus) == true)
    {
        if (fastBootStatus == 0x00000000)
        {
            Helper::printSuccess("- Fast Boot is disabled", false);
            return;
        }
    }

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000000; // Value that will be set for the HiberbootEnabled registry key

    // Create the registry key needed for editing Power Settings settings with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", // Subkey name
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &disp);

    // Set the value of HiberbootEnabled
    LONG createDWORD = RegSetValueEx(hKey,
        "HiberbootEnabled", // Name of value to be set
        NULL,
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value));

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
            Helper::printSuccess("- Successfully disabled Fast Boot", true);
            Helper::restartRequired = true;
            return;
        default:
            // Print error
            Helper::printError("- Failed to disable Fast Boot (Error: 1, " + std::to_string(createDWORD) + ")");
            return;
        }
    default:
        // Print error
        Helper::printError("- Failed to disable Fast Boot (Error: 0, " + std::to_string(createKey) + ")");
        return;
    }
}
void Checks::checkExploitProtection()
{
    SetConsoleTitleA("Checking Exploit-Protection");

    DWORD exploitProtectionStatus;

    // Read the value of the DisallowExploitProtectionOverride registry key
    // This key determines whether Exploit Protection is enabled or disabled
    if (Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection", // Subkey name
        "DisallowExploitProtectionOverride", // DWORD name
        &exploitProtectionStatus) == true)
    {
        if (exploitProtectionStatus == 0x00000001)
        {
            Helper::printSuccess("- Exploit Protection is disabled", false);
            return;
        }
    }

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000001; // Value that will be set for the DisallowExploitProtectionOverride registry key

    // Create the registry key needed for editing Exploit Protection settings with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection", // Subkey name
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &disp);

    // Set the value of DisallowExploitProtectionOverride
    LONG createDWORD = RegSetValueEx(hKey,
        "DisallowExploitProtectionOverride", // Name of value to be set
        NULL,
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value));

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
            Helper::printSuccess("- Successfully disabled Exploit Protection", true);
            Helper::restartRequired = true;
            return;
        default:
            // Print error
            Helper::printError("- Failed to disable Exploit Protection (Error: 1, " + std::to_string(createDWORD) + ")");
            return;
        }
    default:
        // Print error
        Helper::printError("- Failed to disable Exploit Protection (Error: 0, " + std::to_string(createKey) + ")");
        return;
    }
}
void Checks::checkSmartScreen()
{
    SetConsoleTitleA("Checking SmartScreen");

    DWORD smartScreenStatus;

    // Read the value of the EnableSmartScreen registry key
    // This key determines whether Smartscreen is enabled or disabled
    if (Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System", // Subkey name
        "EnableSmartScreen", // DWORD name
        &smartScreenStatus) == true)
    {
        if (smartScreenStatus == 0x00000000)
        {
            Helper::printSuccess("- SmartScreen is disabled", false);
            return;
        }
    }

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000000; // Value that will be set for the EnableSmartScreen registry key

    // Create the registry key needed for editing SmartScreen with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System", // Subkey name
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &disp);

    // Set the value of EnableSmartScreen
    LONG createDWORD = RegSetValueEx(hKey,
        "EnableSmartScreen", // Name of value to be set
        NULL,
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value));

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
            Helper::printSuccess("- Successfully disabled SmartScreen", true);
            Helper::restartRequired = true;
            return;
        default:
            // Print error
            Helper::printError("- Failed to disable SmartScreen (Error: 1, " + std::to_string(createDWORD) + ")");
            return;
        }
    default:
        // Print error
        Helper::printError("- Failed to disable SmartScreen (Error: 0, " + std::to_string(createKey) + ")");
        return;
    }
}
void Checks::checkGameBar()
{
    // Run the powershell command to install the latest Xbox app
    SetConsoleTitleA("Downloading Latest XBox App");
    Helper::runSystemCommand("start powershell.exe -ArgumentList \"Get - AppxPackage Microsoft.XboxApp | Foreach{ Add - AppxPackage - DisableDevelopmentMode - Register \"\"$($_.InstallLocation)\\AppXManifest.xml\"\" }\"");
    // Run the powershell command to install the latest Xbox Gamebar app
    SetConsoleTitleA("Downloading Latest XBox Gamebar App");
    Helper::runSystemCommand("start powershell.exe -ArgumentList \"Get - AppxPackage Microsoft.XboxGameOverlay | Foreach{ Add - AppxPackage - DisableDevelopmentMode - Register \"\"$($_.InstallLocation)\AppXManifest.xml\"\" }\"");

    SetConsoleTitleA("Checking XBox Gamebar");

    DWORD gamebarStatus;

    // Read the value of the AppCaptureEnabled registry key
    // This key determines whether the Xbox Gamebar is enabled or disabled
    if (Helper::readDwordValueRegistry(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR", // Subkey name
        "AppCaptureEnabled", // DWORD name
        &gamebarStatus) == true)
    {
        if (gamebarStatus == 0x00000001)
        {
            Helper::printSuccess("- Gamebar is enabled", false);
            return;
        }
    }

    HKEY hKey;
    DWORD disp;
    DWORD value = 0x00000001; // Value that will be set for the AppCaptureEnabled registry key

    // Create the registry key needed for editing Xbox Gamebar settings with registry
    LONG createKey = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR", // Subkey name
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        NULL,
        &hKey,
        &disp);

    // Set the value of AppCaptureEnabled
    LONG createDWORD = RegSetValueEx(hKey,
        "AppCaptureEnabled", // Name of value to be set
        NULL,
        REG_DWORD, // Value type
        (const BYTE*)&value, // Value data
        sizeof(value));

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
            Helper::printSuccess("- Successfully enabled Gamebar", true);
            Helper::restartRequired = true;
            return;
        default:
            // Print error
            Helper::printError("- Failed to enable Gamebar (Error: 1, " + std::to_string(createDWORD) + ")");
            return;
        }
    default:
        // Print error
        Helper::printError("- Failed to enable Gamebar (Error: 0, " + std::to_string(createKey) + ")");
        return;
    }
}

// All Helper namespace functions
void Helper::setupConsole()
{
    // Get a handle to the console's input buffer
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

    // Disable text selection in the console completely
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS));

    // Set the console title
    SetConsoleTitleA("Initializing");
}
void Helper::printSuccess(const std::string& message, bool changed)
{
    // Set the text color to green for the "[+]"
    Color::setForegroundColor(Color::Green);
    std::cout << "[+] ";
    // Set the text color to white for the message
    Color::setForegroundColor(Color::White);
    std::cout << message;
    // If changed is true print the extra changed message
    if (changed)
    {
        Color::setForegroundColor(Color::Yellow);
        std::cout << " (CHANGED)" << std::endl;
    }
    else
        std::cout << std::endl;
}
void Helper::printConcern(const std::string& message)
{
    // Set the text color to yellow for the "[+]"
    Color::setForegroundColor(Color::Yellow);
    std::cout << "[-] ";
    // Set the text color to white for the message
    Color::setForegroundColor(Color::White);
    std::cout << message << std::endl;
}
void Helper::printError(const std::string& message)
{
    // Set the text color to red for the "[+]"
    Color::setForegroundColor(Color::Red);
    std::cout << "[X] ";
    // Set the text color to white for the message
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
        // If stream is null return
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
