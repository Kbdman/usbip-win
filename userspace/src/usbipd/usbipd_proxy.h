/*
 * usbipd_proxy.h
 *
 *  Created on: Nov 13, 2018
 *      Author: root
 */

#ifndef SRC_USBIPD_PROXY_H_
#define SRC_USBIPD_PROXY_H_

#include <sys/types.h>
//#include <sysfs/libsysfs.h>
#include <stdint.h>


 //#define PROXY_SERV_IPADDR   "47.99.168.209"
 //#define PROXY_SERV_PORT     33340
#define ONLINE_RSP_TIMEOUT  120   //sec
#define CONNECT_TIMEOUT     30   //sec
#define PROTOC_VERSION      0x0111
#define RESERVE_CODE        0x0000

enum
{
	ONLINE_REQ_CMD_CODE = 0x0001,
	ONLINE_REPLY_CMD_CODE = 0x1001,
	ONLINE_SUCESS_RSP_CODE = 0x0000,
};

enum
{
	PROCESS_FAILED = -1,
	COMPLETED_8005_REQ = 0,
	COMPLETED_8003_REQ = 1,
	COMPLETED_9005_REQ = 2,
	COMPLETED_9003_REQ = 3,
};

enum
{
	RECV_TIMEOUT = -1,
	RECV_ERR = -2,
	PROXY_SERVER_CLOSED_CONNECT = -3,  //服务端主动关闭连接
};

#pragma pack(push,1)
typedef struct OnlineReqCommand
{
	uint16_t ver;          //协议版本 固定0x1111
	uint16_t cbSize;      //命令长度（包含协议头和长度）
	uint16_t cmd;        //本帧命令
	uint16_t reserved;  //保留字段 0x0000
	char dev_sn[64];
	char busid[32];
	char reserved_opt[169];
}ONLINE_CMD_REQ_PKT;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct OnlineRspCommand
{
	uint16_t ver;           //协议版本 固定0x1111
	uint16_t cbSize;       //命令长度（包含协议头和长度）
	uint16_t cmd;         //本帧命令
	uint16_t reply_code;  //执行结果 0x1001

}ONLINE_CMD_RSP_PKT;
#pragma pack(pop)


#pragma pack(push,1)
typedef struct usb_info
{
	char dev_sn[64];
	char busid[32];
}USB_INFO;
#pragma pack(pop)


//////////////////监听agent进程消息/////////////////////
int start_usbipd_client_mode();

void printHex(void* buff, uint16_t buff_len);

#endif /* SRC_USBIPD_PROXY_H_ */
