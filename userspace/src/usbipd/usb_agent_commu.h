#pragma once
#ifndef SRC_USB_AGENT_COMMU_H_
#define SRC_USB_AGENT_COMMU_H_

#define MAX_RECV_BYTES      1024
#define MAX_ARGS_SIZE       512
#define AGENT_COMMUN_TCP_PORT   18877
#define BACKLOG  20
#define USBIPD_AGENT_COMMU_VERSION   "usbipd_agent_v1.0"
#define OPEN_PORT_CMD                "open_port"

enum
{
	OPEN_PORT = 1000,        //打开usb端口
	OPEN_PORT_REPLY = 1001,
};

enum
{
	SUCCESS_REPLY_CODE = 100,
	FAILED_REPLY_CODE = 101,
};
#pragma pack(push, 1)
typedef struct usbipd_agent_commu_req
{
	char version[32];
	uint16_t data_len;
	uint16_t  cmd;
	uint8_t  args[MAX_ARGS_SIZE];
}USBIPD_AGENT_COMMU_REQ;


typedef struct usb_agent_open_port_cmd
{
	char dev_sn[64];
	char busid[32];
	char tran_mode[16];
	char proxy_server_addr[200];
	char server_port[6];
	char session_id[128];
}USB_AGENT_OPEN_PORT_CMD;

typedef struct usbipd_agent_commu_rsp
{
	char      version[32];
	uint16_t  data_len;
	uint16_t  cmd;
	uint8_t   result;      //失败:-100  成功: 100
	char args[200];
} USBIPD_AGENT_COMMU_RSP;
#pragma pack(pop)
#endif // !SRC_USB_AGENT_COMMU_H_
