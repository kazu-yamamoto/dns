#ifndef DNS_HS_H
#define DNS_HS_H

#include <windows.h>

typedef struct {
  DWORD error;
  char* dnsAddresses;
} dns_t;

#endif
