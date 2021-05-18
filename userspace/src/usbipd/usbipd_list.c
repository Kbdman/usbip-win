#include "usbipd.h"

#include "usbip_network.h"
#include "usbipd_stub.h"

typedef struct {
	struct usbip_usb_device	udev;
	struct list_head	list;
} edev_t;

static int
send_reply_devlist_devices(SOCKET connfd, struct list_head *pedev_list)
{
	struct list_head	*p;
	struct usbip_usb_interface intf0;
	list_for_each(p, pedev_list) {
		edev_t	*edev;
		int	rc;

		edev = list_entry(p, edev_t, list);

		BOOL got_intf0=build_compatible_id(&edev->udev, &intf0);
		if (got_intf0 == TRUE)
		{
			edev->udev.bNumInterfaces = 1;
		}
		dump_usb_device(&edev->udev);
		usbip_net_pack_usb_device(1, &edev->udev);

		rc = usbip_net_send(connfd, &edev->udev, sizeof(edev->udev));
		if (rc < 0) {
			dbg("usbip_net_send failed: udev");
			return -1;
		}
		if (got_intf0)
		{
			rc = usbip_net_send(connfd, &intf0, sizeof(intf0));
			if (rc < 0)
			{
				dbg("usbip_net_send failed: interface,");
				return -1;
			}
		}
		/* usb interface count is always zero */
	}
	return 0;
}

typedef struct {
	struct list_head	*head;
	int	n_edevs;
} edev_list_ctx_t;

static int
walker_edev_list(HDEVINFO dev_info, PSP_DEVINFO_DATA pdev_info_data, devno_t devno, void *ctx)
{
	edev_t	*edev;
	edev_list_ctx_t	*pctx = (edev_list_ctx_t *)ctx;

	edev = (edev_t *)malloc(sizeof(edev_t));
	if (edev == NULL) {
		dbg("out of memory");
		return 0;
	}
	if (!is_stub_devno(devno))
		return 0;
	if (!build_udev(devno, &edev->udev)) {
		dbg("cannot build usbip dev");
		free(edev);
		return 0;
	}
	list_add(&edev->list, pctx->head->prev);
	pctx->n_edevs++;
	return 0;
}

static void
get_edev_list(struct list_head *head, int *pn_edevs)
{
	edev_list_ctx_t	ctx;

	INIT_LIST_HEAD(head);
	ctx.head = head;
	ctx.n_edevs = 0;
	traverse_usbdevs(walker_edev_list, TRUE, &ctx);
	*pn_edevs = ctx.n_edevs;
}

static void
free_edev_list(struct list_head *head)
{
	struct list_head	*p, *n;

	list_for_each_safe(p, n, head) {
		edev_t	*edev;

		edev = list_entry(p, edev_t, list);
		list_del(&edev->list);
		free(edev);
	}
}

static int
send_reply_devlist(SOCKET connfd)
{
	struct op_devlist_reply		reply;
	struct list_head	edev_list;
	int	n_edevs;
	int	rc;

	get_edev_list(&edev_list, &n_edevs);
	dbg("exportable devices: %d", n_edevs);

	reply.ndev = n_edevs;

	rc = usbip_net_send_op_common(connfd, OP_REP_DEVLIST, ST_OK);
	if (rc < 0) {
		dbg("usbip_net_send_op_common failed: %#0x", OP_REP_DEVLIST);
		free_edev_list(&edev_list);
		return -1;
	}
	PACK_OP_DEVLIST_REPLY(1, &reply);

	rc = usbip_net_send(connfd, &reply, sizeof(reply));
	if (rc < 0) {
		dbg("usbip_net_send failed: %#0x", OP_REP_DEVLIST);
		free_edev_list(&edev_list);
		return -1;
	}

	if (send_reply_devlist_devices(connfd, &edev_list) < 0) {
		free_edev_list(&edev_list);
		return -1;
	}

	free_edev_list(&edev_list);
	return 0;
}

int
recv_request_devlist(SOCKET connfd)
{
	int	rc;

	rc = send_reply_devlist(connfd);
	if (rc < 0) {
		dbg("send_reply_devlist failed");
		return -1;
	}

	return 0;
}
int recv_request_devlist_ex(int connfd, struct op_devlist_request_ex* req)
{
	int rc;

	rc = usbip_net_recv(connfd, req, sizeof(struct op_devlist_request_ex));
	if (rc < 0) {
		err("usbip_net_recv failed: recv 0x9005 error: %s", strerror(errno));
		return -1;
	}

	rc = send_reply_devlist(connfd);
	if (rc < 0) {
		err("send_reply_devlist failed, &%s", req->session_id);
		return -1;
	}

	return 0;
}

