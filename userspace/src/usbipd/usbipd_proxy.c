#include "usbipd.h"
#include "usbipd_proxy.h"
#include <ws2tcpip.h>

#include "usbip_network.h"
#include "usb_agent_commu.h"

typedef struct agent_ctx
{
	struct sockaddr_in addr;
	SOCKET sd;
}agentctx;
void printHex(void* buff, uint16_t buff_len)
{
	char* out_buf = NULL;
	char* tmp_buf = (char*)buff;
	int i = 0;
	int k = 0;

	if (!buff || buff_len <= 0)
	{
		return;
	}
	out_buf = (char*)malloc(buff_len * 3);
	if (!out_buf)
	{
		err("%s -> failed to malloc ,errno=[%d]", __FUNCTION__, errno);
		return;
	}
	memset(out_buf, 0, buff_len * 3);
	for (i = 0; i < buff_len; i++)
	{
		k += snprintf(out_buf + k, buff_len * 3 - k, "%02x ", tmp_buf[i]);
	}
	out_buf[k - 1] = '\0';
	info("[printHex] [%s]", out_buf);

	if (out_buf)
	{
		free(out_buf);
		out_buf = NULL;
	}

	return;
}
static int send_reply_msg_to_agent_process(int connfd, USBIPD_AGENT_COMMU_RSP* reply)
{
	int ret = 0;


	ret = send(connfd, reply, sizeof(USBIPD_AGENT_COMMU_RSP), 0); //send data to agent
	if (ret <= 0) {
		err("[socket:%d] Send open port reply to agent process failed: %s !!!", connfd, strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * 连接转发服务
 */
static int connect_to_extranet(const char* ipaddr, uint16_t port)
{
	int sockfd = -1;
	int ret;
	struct sockaddr_in serv_addr;
	struct timeval timeout;
	socklen_t len = sizeof(timeout);


	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		err("Failed to create client fd,errno=[%d]\n", errno);
		return -1;
	}

	memset(&serv_addr, 0, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ipaddr);
	timeout.tv_sec = CONNECT_TIMEOUT;
	timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, len);
	usbip_net_set_keepalive(sockfd);
	ret = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(struct sockaddr));
	if (ret < 0)
	{
		return -1;
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, len);
	return sockfd;
}
/*
 * 发送联机命令,指明sn和busid
 */
static int send_online_cmd(const int client_sockfd, const char* dev_sn, const char* busid)
{
	ONLINE_CMD_REQ_PKT send_pkt;
	int s_size = 0;
	int ret = 0;
	int data_len = 0;

	if (client_sockfd == -1 || strlen(dev_sn) <= 0 || strlen(busid) <= 0)
	{
		return -1;
	}
	memset(&send_pkt, 0, sizeof(ONLINE_CMD_REQ_PKT));
	data_len = sizeof(ONLINE_CMD_REQ_PKT);
	send_pkt.ver = htons(PROTOC_VERSION);
	send_pkt.cbSize = htons(sizeof(ONLINE_CMD_REQ_PKT));
	send_pkt.cmd = htons(ONLINE_REQ_CMD_CODE);
	send_pkt.reserved = htons(RESERVE_CODE);
	strcpy(send_pkt.dev_sn, dev_sn);
	strcpy(send_pkt.busid, busid);
	memset(send_pkt.reserved_opt, 0, 169);
	do {
		info("");
		info("----------------------------send online req to proxy server--------------------------");
		s_size = send(client_sockfd, (void*)&send_pkt, data_len, 0);
		if (s_size == 0)
		{
			err("\n#####[socket:%d] Proxy server closed tcp connection,ret=%d,errno=%d,error:%s#####\n",
				client_sockfd, s_size,
				errno, strerror(errno));
			ret = -1;
			break;
		}
		//发生错误
		else if (-1 == s_size)
		{
			if (errno == EINTR)
			{
				s_size = 0;
				continue;
			}
			else
			{
				err("\n[socket:%d] failed to send online,errno[%d],error: %s\n", client_sockfd, errno, strerror(errno));
				ret = -1;
				break;
			}
		}
	} while (0);

	if (s_size != data_len)
	{
		err("[socket:%d] Incomplete sending data,send size: %d, total_data size: %d", client_sockfd, s_size, data_len);
		ret = -1;
	}
	else
	{
		ret = s_size;
		info("[socket:%d] send online req data size: %d bytes ", client_sockfd, s_size);
		printHex((void*)&send_pkt, data_len);
		info("----------------------------------------------------------------------------------------");
	}

	return ret;
}
/*
 * 接收联机应答
 */
static int recv_online_rsp(const int sockfd, ONLINE_CMD_RSP_PKT* recv_buff, int buff_len)
{
	int nbytes = 0;
	struct timeval timeout;

	void* buff = malloc(buff_len);
	if (!buff)
	{
		err("[socket:%d]malloc failed: %s", sockfd, strerror(errno));
		return -1;
	}

	timeout.tv_sec = ONLINE_RSP_TIMEOUT;   //防止连接异常断开recv一直阻塞
	timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	nbytes = recv(sockfd, buff, buff_len, MSG_WAITALL);
	if (nbytes == -1)
	{
		if (errno == EAGAIN)
		{
			return  RECV_TIMEOUT;
		}
		else {
			return RECV_ERR;
		}
	}
	else if (nbytes == 0)
	{
		return PROXY_SERVER_CLOSED_CONNECT;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
	info("[socket:%d] recv online rsp data size: %d bytes", sockfd, buff_len);
	printHex(buff, buff_len);

	memcpy(recv_buff, buff, buff_len);
	if (buff)
	{
		free(buff);
	}

	return nbytes;
}
/*
 * 解析联机应答
 */
static int parse_online_rsp_pkt(ONLINE_CMD_RSP_PKT* recv_pkt, uint16_t pkt_size)
{
	int ret = 0;

	if (!recv_pkt || pkt_size <= 0)
	{
		err("[parse_online_rsp_pkt] invalid args,recv_pkt=%p,pkt_size:%d\n", recv_pkt, pkt_size);
		return -1;
	}
	if (htons(recv_pkt->ver) == PROTOC_VERSION)
	{
		switch (htons(recv_pkt->cmd))
		{
		case ONLINE_REPLY_CMD_CODE:     //联机应答命令 0x1001
			info("[parse_online_rsp_pkt] Receive online rsp code: 0x%04x\n",  ONLINE_SUCESS_RSP_CODE);
			if (htons(recv_pkt->reply_code) == ONLINE_SUCESS_RSP_CODE)
			{
				ret = 0;
			}
			else
			{
				ret = -1;
				err("[parse_online_rsp_pkt] Request online failed，reply code: %d", htons(recv_pkt->reply_code));
			}
			break;
		default:
			ret = -1;
			err("[parse_online_rsp_pkt] Unsupport online reply cmd: 0x%04x !!!\n",  htons(recv_pkt->cmd));
			break;
		}
	}
	else {
		err("[parse_online_rsp_pkt] Unsupport protocol version: 0x%04x",  htons(recv_pkt->ver));
		ret = -1;
	}

	return ret;
}

/*
 * 处理联机任务
 */
static int handle_online(const int sockfd, const char* dev_sn, const char* busid)
{
	int ret = 0;
	int nbytes = 0;
	ONLINE_CMD_RSP_PKT recv_pkt;

	memset(&recv_pkt, 0, sizeof(ONLINE_CMD_RSP_PKT));
	//向转发服务发送要连机的sn和busid
	nbytes = send_online_cmd(sockfd, dev_sn, busid);
	if (nbytes < 0)
	{
		closesocket(sockfd);
		return -1;
	}
	info("");
	info("-----------------------recv online rsp from proxy server----------------------------");
	nbytes = recv_online_rsp(sockfd, &recv_pkt, sizeof(ONLINE_CMD_RSP_PKT));
	switch (nbytes)
	{
	case RECV_TIMEOUT:
		err("########[socket:%d] Recv online rsp timeout(%ds)########", sockfd, ONLINE_RSP_TIMEOUT);
		ret = -1;
		closesocket(sockfd);
		break;
	case RECV_ERR:
		err("########[socket:%d]Recv online rsp error: %s########", sockfd, strerror(errno));
		closesocket(sockfd);
		ret = -1;
		break;
	case PROXY_SERVER_CLOSED_CONNECT:
		err("########[socket:%d] Recv online rsp failed: proxy server closed tcp connection########", sockfd);
		closesocket(sockfd);
		ret = -1;
		break;
	}
	if (nbytes > 0)
	{
		ret = parse_online_rsp_pkt(&recv_pkt, sizeof(ONLINE_CMD_RSP_PKT));
		if (ret < 0)
		{
			err("[socket:%d] Parse online rsp pkt failed !!!", sockfd);
			return -1;
		}
		else {
			info("[socket:%d] req proxy server online success !!!", sockfd);
		}
	}
	info("--------------------------------------------------------------------------------------");

	return ret;
}
static int recv_pdu_ex(int sockfd, const char* session_id)
{
	int ret = PROCESS_FAILED;
	uint16_t code = OP_UNSPEC;
	struct op_devlist_request_ex req_devlist;
	struct op_import_request_ex req_import;

	memset(&req_devlist, 0, sizeof(req_devlist));
	memset(&req_import, 0, sizeof(req_import));

	do {
		int status;
		ret = usbip_net_recv_op_common(sockfd, &code, &status);
		if (ret < 0) {
			info("[socket:%d] could not receive opcode: %#0x, cause: %s, &%s", sockfd, code, strerror(errno), session_id);
			ret = PROCESS_FAILED;
			break;
		}
		/*
		* 没有主动刷星设备列表功能，先注释
		ret = usbip_host_refresh_device_list();
		if (ret < 0) {
			info("[socket:%d] could not refresh device list: %d, &%s", sockfd, ret, session_id);
			ret = PROCESS_FAILED;
			break;
		}
		*/
		switch (code)
		{
		case OP_REQ_DEVLIST:
			ret = recv_request_devlist(sockfd, session_id);
			if (ret == 0) {
				ret = COMPLETED_8005_REQ;
				info("[socket:%d] Complete %#0x request(sockfd: %d), &%s", sockfd, code, sockfd, session_id);
			}
			break;
		case OP_REQ_IMPORT:
			ret = recv_request_import(sockfd, session_id);
			if (ret == 0) {
				ret = COMPLETED_8003_REQ;
				info("[socket:%d] Complete %#0x request(sockfd: %d), &%s", sockfd, code, sockfd, session_id);
			}
			break;
		case OP_REQ_DEVLIST_EX:
			ret = recv_request_devlist_ex(sockfd, &req_devlist);
			if (ret == 0) {
				ret = COMPLETED_9005_REQ;
				info("[socket:%d] Complete %#0x request(sockfd: %d), &%s", sockfd, code, sockfd, session_id);
			}
			break;
		case OP_REQ_IMPORT_EX:
			ret = recv_request_import_ex(sockfd, &req_import);
			if (ret == 0) {
				ret = COMPLETED_9003_REQ;
				info("[socket:%d] Complete %#0x request(sockfd: %d), &%s", sockfd, code, sockfd, session_id);
			}
			break;
		case OP_REQ_DEVINFO:
		case OP_REQ_CRYPKEY:
		default:
			err("[socket:%d] Received an unknown opcode: %#0x, &%s", sockfd, code, session_id);
			ret = PROCESS_FAILED;
		}
		if (ret < 0) {
			info("[socket:%d] Request(sockfd: %d) %#0x: failed, &%s", sockfd, sockfd, code, session_id);
		}
	} while (0);

	return ret;
}
/*
	转发方式
	处理8005,8003
	处理9005,9003
 */
static int handle_devlist_import_cmd(int sockfd, const char* session_id)
{
	int terminate = 0;
	fd_set fd_r;
	int ret = 0;
	int result = 0;
	uint16_t wait_req_code = OP_REQ_DEVLIST;

	if (sockfd < 0) {
		return -1;
	}
	wait_req_code = (strlen(session_id) > 0 ? OP_REQ_DEVLIST_EX : OP_REQ_DEVLIST);

	while (!terminate)
	{
		FD_ZERO(&fd_r);
		FD_SET(sockfd, &fd_r);

		info("[socket:%d] wait recv 0x%04x request, &%s", sockfd, wait_req_code, session_id);
		ret = select(sockfd + 1, &fd_r, NULL, NULL, NULL);
		if (ret < 0) //出错
		{
			if (errno == EINTR) {
				info("[socket:%d] select signal interrupt, &%s", sockfd, session_id); //select阻塞被信号中断
				continue;
			}
			err("[socket:%d] Failed to select: %s, &%s", sockfd, strerror(errno), session_id);
			terminate = 1;
			ret = -1;
		}
		else if (ret == 0) //超时
		{
			err("[socket:%d] Wait 0x%04x request timeout, &%s", sockfd, wait_req_code, session_id);
			terminate = 1;
			ret = -1;
		}
		else
		{
			if (FD_ISSET(sockfd, &fd_r))
			{
				result = recv_pdu_ex(sockfd, session_id);
				switch (result)
				{
				case COMPLETED_8005_REQ:
					wait_req_code = OP_REQ_IMPORT;
					break;
				case COMPLETED_8003_REQ:
					terminate = 1; //8005 8003处理完成，退出
					break;
				case COMPLETED_9005_REQ:
					wait_req_code = OP_REQ_IMPORT_EX;
					break;
				case COMPLETED_9003_REQ:
					terminate = 1; //9005 9003处理完成，退出
					break;
				default:
					err("######[socket:%d] Failed to handle %#0x request######, &%s", sockfd, wait_req_code, session_id);
					ret = -1;
					terminate = 1;
				}
			}
		}
	}

	return ret;
}
//转发服务模式
static int  do_tran_server_mode(int agent_connfd, USB_AGENT_OPEN_PORT_CMD* info)
{
	int sockfd = -1;
	int ret;
	int proxy_port = atoi(info->server_port);
	USBIPD_AGENT_COMMU_RSP reply;


	info("[socket:%d]  start  proxy server mode, &%s", agent_connfd, info->session_id);
	memset(&reply, 0, sizeof(USBIPD_AGENT_COMMU_RSP));
	strcpy(reply.version, USBIPD_AGENT_COMMU_VERSION);
	reply.cmd = OPEN_PORT_REPLY;
	reply.data_len = sizeof(USBIPD_AGENT_COMMU_RSP);
	reply.result = SUCCESS_REPLY_CODE;
	do {
		sockfd = connect_to_extranet(info->proxy_server_addr, proxy_port);
		if (sockfd < 0)
		{
			info("");
			err("######[socket: %d] Failed to connect to proxy server(%s:%d): %s ####### &%s", agent_connfd, info->proxy_server_addr, proxy_port, strerror(errno), info->session_id);
			info("");
			ret = -1;
			reply.result = FAILED_REPLY_CODE;
			break;
		}
		info("[socket:%d] Connect to proxy server(%s,%d) success, &%s", agent_connfd, info->proxy_server_addr, proxy_port, info->session_id);
		ret = handle_online(sockfd, info->dev_sn, info->busid);
		if (ret < 0)
		{
			ret = -1;
			reply.result = FAILED_REPLY_CODE;
			closesocket(sockfd);
			break;
		}
		else {
			reply.result = SUCCESS_REPLY_CODE;
		}
	} while (0);

	send_reply_msg_to_agent_process(agent_connfd, &reply);

	if (ret < 0) {
		return -1;
	}
	else {
		ret = handle_devlist_import_cmd(sockfd, info->session_id);
		if (ret < 0) {
			info("[socket:%d] Close proxy server connection", (int)getpid());
			closesocket(sockfd);
			return -1;
		}
	}

	return 0;
}
static int handle_open_port_task(int connfd, USB_AGENT_OPEN_PORT_CMD* info)
{
	int ret = 0;
	USBIPD_AGENT_COMMU_RSP reply;

	memset(&reply, 0, sizeof(USBIPD_AGENT_COMMU_RSP));
	strcpy(reply.version, USBIPD_AGENT_COMMU_VERSION);
	reply.cmd = OPEN_PORT_REPLY;
	reply.data_len = sizeof(USBIPD_AGENT_COMMU_RSP);


	if (!info) {
		err("invalid info=%p\n", info);
		return -1;
	}
	info("[socket:%d] sn: %s,busid: %s,tran_mode:%s, addr: %s,port: %s, &%s", connfd,
		info->dev_sn,
		info->busid, info->tran_mode,
		info->proxy_server_addr, info->server_port,
		info->session_id);
	if (strcmp(info->tran_mode, "0") == 0) {
		ret = do_tran_server_mode(connfd, info);
	}
	else if (strcmp(info->tran_mode, "1") == 0) {
		ret = do_port_forwarding_mode(connfd, info);
	}
	else {
		err("[socket:%d] invalid tran mode: %s, &%s", connfd, info->tran_mode, info->session_id);
		ret = -1;
		reply.result = FAILED_REPLY_CODE;
		send_reply_msg_to_agent_process(connfd, &reply);
	}

	return ret;
}
static void do_client_req_task(SOCKET connfd, void* recv_data, uint16_t data_len,PTP_WORK work)
{
	USBIPD_AGENT_COMMU_REQ req;
	USB_AGENT_OPEN_PORT_CMD payload;
	int ret = 0;

	if (!recv_data || data_len <= 0 || data_len > sizeof(USBIPD_AGENT_COMMU_REQ))
	{
		return;
	}
	memset(&req, 0, sizeof(USBIPD_AGENT_COMMU_REQ));
	memcpy(&req, recv_data, data_len);
	if (strcmp(req.version, USBIPD_AGENT_COMMU_VERSION) != 0)
	{
		err("[work:%p] Unsupport usbipd_agent_commu protol version: %s", work, req.version);
		return;
	}
	switch (req.cmd)
	{
	case OPEN_PORT:
		memset(&payload, 0, sizeof(USB_AGENT_OPEN_PORT_CMD));
		memcpy(&payload, req.args, sizeof(USB_AGENT_OPEN_PORT_CMD));
		//enable_log_uplaod_yun(payload.dev_sn);		
		info("[work:%p] Handle open port: %s request,&%s", connfd, payload.busid, payload.session_id);

		ret = handle_open_port_task(connfd, &payload);
		if (ret == 0) {
			info("[socket:%d] Complete open port: %s request,&%s", connfd, payload.busid, payload.session_id);
			info("");
		}
		else {
			info("");
			info("#####[socket:%d] Failed to handle open port: %s request#####,&%s", connfd, payload.busid, payload.session_id);
			info("");
		}
		break;
	default:
		err("[socket:%d] Unsupport cmd :%d", connfd, req.cmd);
		break;
	}

	return;
}

VOID CALLBACK handle_client(
	_Inout_     PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PVOID                 Context,
	_Inout_     PTP_WORK              Work
)
{
	UNREFERENCED_PARAMETER(Instance);
	agentctx* ctx = Context;
	char recv_buff[MAX_RECV_BYTES];
	int recv_bytes = 0;
	int terminate = 0;
	SOCKET connfd = ctx->sd;

	memset(recv_buff, 0, MAX_RECV_BYTES);
	while (!terminate)
	{
		recv_bytes = recv(connfd, recv_buff, MAX_RECV_BYTES, 0);
		if (recv_bytes < 0) {
			err("[work:%p] Recv agent process msg error: %s", Work, strerror(errno));
			terminate = 1;
		}
		else if (recv_bytes == 0)
		{
			info("[work:%p] agent process(%s:%d) close connection",
				Work,
				inet_ntoa(ctx->addr.sin_addr),
				ntohs(ctx->addr.sin_port));
			terminate = 1;
		}
		else
		{
			do_client_req_task(connfd, recv_buff, recv_bytes, Work);
		}
	}

	return;
}
static int create_listen_sock()
{
	SOCKET sockfd = -1;
	int reuse = 1;
	struct sockaddr_in server_sockaddr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		err("%s Failed to socket(): %s", __FUNCTION__, strerror(errno));
		return -1;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0)
	{
		err("Failed to setsockopt: %s", strerror(errno));
		return -1;
	}
	memset(&server_sockaddr,0, sizeof(server_sockaddr));
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(AGENT_COMMUN_TCP_PORT);

	if (bind(sockfd, (struct sockaddr*)&server_sockaddr, sizeof(struct sockaddr_in)) < 0)
	{
		err("%s Failed to bind(): %s", __FUNCTION__, strerror(errno));
		closesocket(sockfd);
		return -1;
	}
	if (listen(sockfd, BACKLOG) < 0)
	{
		err("%s Failed to listen(): %s", __FUNCTION__, strerror(errno));
		closesocket(sockfd);
		return -1;
	}

	return sockfd;
}

int start_usbipd_client_mode()
{
	int terminate = 0;
	SOCKET listen_sock = -1;
	int connfd = -1;

	info("starting " PROGNAME " (%s) client mode", PACKAGE_STRING);
	listen_sock = create_listen_sock();
	if (listen_sock < 0) {
		return -1;
	}
	while (!terminate)
	{
		agentctx* ctx=malloc(sizeof(agentctx));
		if (ctx == NULL)
		{
			err("Fail to allocate agentctx");
			continue;
		}
		socklen_t addr_len = sizeof(struct sockaddr_in);
		connfd = accept(listen_sock, (struct sockaddr*)&(ctx->addr), &addr_len);
		if (connfd < 0)
		{
			if (errno == EINTR) {
				err("####accept signal interrupt####"); //accept阻塞被linux信号中断
				//continue;
			}
			err("%s Failed to accept(): %s", __FUNCTION__, strerror(errno));
			return -1;
		}
		info("Accept client (%s:%d) connection", inet_ntoa(ctx->addr.sin_addr), ntohs(ctx->addr.sin_port));
		PTP_WORK work= CreateThreadpoolWork(handle_client, ctx, NULL);
		if (work == NULL) {
			dbg("failed to create thread pool work: error: %lx", GetLastError());
			closesocket(connfd);
			free(ctx);
			return ERR_GENERAL;
		}
		SubmitThreadpoolWork(work);
	}

	return 0;
}