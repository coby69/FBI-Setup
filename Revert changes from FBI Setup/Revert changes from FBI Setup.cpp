#include <Windows.h>
#include <iostream>

int main() {
    // Get the state of the Windows Defender service
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        std::cerr << "Error opening Service Control Manager: " << GetLastError() << std::endl;
        return 1;
    }
    SC_HANDLE service = OpenService(scm, L"WinDefend", SERVICE_QUERY_STATUS);
    if (service == NULL) {
        std::cerr << "Error opening Windows Defender service: " << GetLastError() << std::endl;
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        std::cerr << "Error querying Windows Defender service status: " << GetLastError() << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }

    // Print the state of the Windows Defender service
    if (status.dwCurrentState == SERVICE_RUNNING) {
        std::cout << "Windows Defender is enabled" << std::endl;
    }
    else {
        std::cout << "Windows Defender is disabled" << std::endl;
    }

    // Close the handles
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    system("pause");

    return 0;
}
