#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

typedef struct {
    char* buffer;
    size_t size;
} CommandOutput;


BOOL isDirectoryExcluded(const char* dirPath) {
    char command[MAX_PATH * 2];
    BOOL isExcluded = FALSE;


    StringCchPrintfA(command, MAX_PATH * 2,
        "\"%s\" -Scan -ScanType 3 -File \"%s\\*\"",
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
        dirPath);


    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr = {
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .bInheritHandle = TRUE,
        .lpSecurityDescriptor = NULL
    };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        return FALSE;
    }


    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;


    if (CreateProcessA(NULL, (LPSTR)command, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

        CloseHandle(hWritePipe);


        char buffer[4096];
        DWORD bytesRead;
        char outputBuffer[8192] = { 0 };
        size_t totalRead = 0;

        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            if (bytesRead == 0) break;

            if (totalRead + bytesRead < sizeof(outputBuffer) - 1) {
                memcpy(outputBuffer + totalRead, buffer, bytesRead);
                totalRead += bytesRead;
                outputBuffer[totalRead] = '\0';
            }
        }

        if (strstr(outputBuffer, "was skipped")) {
            isExcluded = TRUE;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hReadPipe);
    return isExcluded;
}

void findExcludedDirectories(const char* basePath) {
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA findData;

    StringCchPrintfA(searchPath, MAX_PATH, "%s\\*", basePath);

    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    if (isDirectoryExcluded(basePath)) {
        printf("Excluded: %s\n", basePath);
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(findData.cFileName, ".") != 0 &&
                strcmp(findData.cFileName, "..") != 0) {

                char newPath[MAX_PATH];
                StringCchPrintfA(newPath, MAX_PATH, "%s\\%s", basePath, findData.cFileName);

                findExcludedDirectories(newPath);
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    DWORD attrs = GetFileAttributesA(argv[1]);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("Error: Directory does not exist or is not accessible: %s\n", argv[1]);
        return 1;
    }

    printf("Scanning for excluded directories starting from: %s\n\n", argv[1]);
    findExcludedDirectories(argv[1]);

    printf("\nScan complete. Press Enter to exit...");
    getchar();
    return 0;
}