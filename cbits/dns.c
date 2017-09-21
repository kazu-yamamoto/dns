#include <winsock2.h>
#include <iphlpapi.h>
#include <string.h>
#include <windows.h>
#include <string.h>

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

// Fills `dnsAddresses` with the DNS addresses found, up to `bufferLen`.
// Returns NO_ERROR (0x0) in case the operation succeeds, otherwise a non-zero
// error code. See: https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
DWORD getWindowsDefDnsServers(char* dnsAddresses, size_t bufferLen) {
    FIXED_INFO *pFixedInfo;
    ULONG ulOutBufLen;
    DWORD dwRetVal;

    if (bufferLen <= 0) return ERROR_NOT_ENOUGH_MEMORY;

    pFixedInfo = (FIXED_INFO *) MALLOC(sizeof (FIXED_INFO));
    if (pFixedInfo == NULL)
      return ERROR_NOT_ENOUGH_MEMORY;
    ulOutBufLen = sizeof (FIXED_INFO);

    // Make an initial call to GetAdaptersInfo to get the necessary size into the
    // ulOutBufLen variable
    if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pFixedInfo);
        pFixedInfo = (FIXED_INFO *) MALLOC(ulOutBufLen);
        if (pFixedInfo == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
    }

    dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);

    if (dwRetVal == NO_ERROR) {
      int offset = 0;
      int spaceAvailable = bufferLen;
      IP_ADDR_STRING* head = &pFixedInfo->DnsServerList;

      while (head != NULL && spaceAvailable >= 16) {
        int ipLen = strlen(head->IpAddress.String);
        int copySize = ipLen + 1;

        // Copy the IP address, including the null terminator.
        strcpy_s(dnsAddresses + offset, copySize, head->IpAddress.String);

        spaceAvailable -= copySize;
        if (spaceAvailable <= 0) break;

        offset += copySize;

        // Write the separator, but only if this is not the last one,
        // otherwise the string is already terminated due to the call to
        // strcpy_s, which copies the null terminator.

        head = head->Next;
        if (head != NULL)
          dnsAddresses[offset - 1] = ',';
      }

    }

    if (pFixedInfo) FREE(pFixedInfo);
    return dwRetVal;
}

/*

// Test with 'gcc -o dnsServer -Wall -Werror -pedantic -liphlpapi -Iinclude dns.c' on a
// Windows machine.

int main(){
    printf(getWindowsDefDnsServers()->dnsAddresses);
    return 0;
}*/
