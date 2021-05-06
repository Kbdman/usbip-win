#pragma once

#include <winsock2.h>
#include <windows.h>

#include "usbip_common.h"
#undef  PROGNAME
#define PROGNAME "usbipd"
extern int recv_request_import(SOCKET sockfd);
extern int recv_request_devlist(SOCKET connfd);

int recv_request_devlist_ex(int connfd, struct op_devlist_request_ex* req);
int recv_request_import_ex(int sockfd, struct op_import_request_ex* req);
