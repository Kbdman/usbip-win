/*
 *
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#define INITGUID

#include "usbip_windows.h"

#include "usbip_common.h"
#include "usbip_stub_api.h"
#include "usbip_setupdi.h"

#include <winsock2.h>
#include <stdlib.h>
#include <winusb.h>
#include <usbspec.h>

typedef struct {
	const char	*id_inst;
	char	*devpath;
} devpath_ctx_t;

static int
walker_devpath(HDEVINFO dev_info, PSP_DEVINFO_DATA pdev_info_data, devno_t devno, void *ctx)
{
	devpath_ctx_t	*pctx = (devpath_ctx_t *)ctx;
	PSP_DEVICE_INTERFACE_DETAIL_DATA	pdetail;
	char	*id_inst;

	id_inst = get_id_inst(dev_info, pdev_info_data);
	if (id_inst == NULL)
		return 0;
	if (strcmp(id_inst, pctx->id_inst) != 0) {
		free(id_inst);
		return 0;
	}
	free(id_inst);

	pdetail = get_intf_detail(dev_info, pdev_info_data, &GUID_DEVINTERFACE_STUB_USBIP);
	if (pdetail == NULL) {
		return 0;
	}
	pctx->devpath = _strdup(pdetail->DevicePath);
	free(pdetail);
	return -1;
}

static char *
get_device_path(const char *id_inst)
{
	devpath_ctx_t	devpath_ctx;
	int rc;

	devpath_ctx.id_inst = id_inst;
	rc = traverse_intfdevs(walker_devpath, &GUID_DEVINTERFACE_STUB_USBIP, &devpath_ctx);
	if (rc != -1) {
		dbg("traverse_intfdevs failed, returned: %d", rc);
		return NULL;
	}

	return devpath_ctx.devpath;
}

static BOOL
get_devinfo(const char *devpath, ioctl_usbip_stub_devinfo_t *devinfo)
{
	HANDLE	hdev;
	DWORD	len;

	hdev = CreateFile(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hdev == INVALID_HANDLE_VALUE) {
		dbg("get_devinfo: cannot open device: %s", devpath);
		return FALSE;
	}
	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_GET_DEVINFO, NULL, 0, devinfo, sizeof(ioctl_usbip_stub_devinfo_t), &len, NULL)) {
		dbg("get_devinfo: DeviceIoControl failed: err: 0x%lx", GetLastError());
		CloseHandle(hdev);
		return FALSE;
	}
	CloseHandle(hdev);

	if (len != sizeof(ioctl_usbip_stub_devinfo_t)) {
		dbg("get_devinfo: DeviceIoControl failed: invalid size: len: %d", len);
		return FALSE;
	}

	return TRUE;
}

typedef struct {
	devno_t	devno;
	char	*id_inst;
} get_id_inst_ctx_t;

static int
walker_get_id_inst(HDEVINFO dev_info, PSP_DEVINFO_DATA pdev_info_data, devno_t devno, void *ctx)
{
	get_id_inst_ctx_t	*pctx = (get_id_inst_ctx_t *)ctx;

	if (devno == pctx->devno) {
		pctx->id_inst = get_id_inst(dev_info, pdev_info_data);
		return -1;
	}
	return 0;
}

static char *
get_devpath_from_devno(devno_t devno)
{
	get_id_inst_ctx_t	ctx;
	char	*devpath;
	int rc;

	ctx.devno = devno;
	rc = traverse_usbdevs(walker_get_id_inst, TRUE, &ctx);
	if (rc != -1) {
		dbg("traverse_usbdevs failed. traverse_usbdevs returned %d.", rc);
		return NULL;
	}

	devpath = get_device_path(ctx.id_inst);
	free(ctx.id_inst);

	return devpath;
}

static int
walker_check_stub(HDEVINFO dev_info, PSP_DEVINFO_DATA pdev_info_data, devno_t devno, void *ctx)
{
	devno_t	*pdevno = (devno_t *)ctx;

	if (*pdevno == devno)
		return 1;
	return 0;
}

BOOL
is_stub_devno(devno_t devno)
{
	int	rc;

	rc = traverse_intfdevs(walker_check_stub, &GUID_DEVINTERFACE_STUB_USBIP, &devno);
	if (rc == 1)
		return TRUE;
	return FALSE;
}
static BOOL get_devconf(const char* devpath, PUSB_CONFIGURATION_DESCRIPTOR cfg, UCHAR index)
{
	dbg("get_devconf dev:%s idx: %d", devpath, index);
	HANDLE	hdev;
	DWORD	len;
	ioctl_usbip_index_param req;
	req.index = index;
	hdev = CreateFile(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hdev == INVALID_HANDLE_VALUE) {
		dbg("get_devconf: cannot open device: %s", devpath);
		return FALSE;
	}
	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_GET_CONFIGINFO, &req, sizeof(ioctl_usbip_index_param), cfg, sizeof(USB_CONFIGURATION_DESCRIPTOR), &len, NULL)) {
		dbg("get_devconf: DeviceIoControl failed: err: 0x%lx", GetLastError());
		CloseHandle(hdev);
		return FALSE;
	}
	CloseHandle(hdev);

	if (len != sizeof(USB_CONFIGURATION_DESCRIPTOR)) {
		dbg("get_devconf: DeviceIoControl failed: invalid size: len: %d", len);
		return FALSE;
	}
	dbg("get_devconf config:%d, intf:%d ", cfg->iConfiguration, cfg->bNumInterfaces);
	return TRUE;
}

static BOOL get_devintf(const char* devpath,PUSB_INTERFACE_DESCRIPTOR intfinfo,UCHAR index)
{
	dbg("get_interfaceinfo dev:%s idx: %d", devpath, index);
	HANDLE	hdev;
	DWORD	len;
	ioctl_usbip_index_param req;
	req.index = index;
	hdev = CreateFile(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hdev == INVALID_HANDLE_VALUE) {
		dbg("get_interfaceinfo: cannot open device: %s", devpath);
		return FALSE;
	}
	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_GET_INTERFACEINFO, &req, sizeof(ioctl_usbip_index_param), intfinfo, sizeof(USB_INTERFACE_DESCRIPTOR), &len, NULL)) {
		dbg("get_interfaceinfo: DeviceIoControl failed: err: 0x%lx", GetLastError());
		CloseHandle(hdev);
		return FALSE;
	}
	CloseHandle(hdev);

	if (len != sizeof(USB_INTERFACE_DESCRIPTOR)) {
		dbg("get_interfaceinfo: DeviceIoControl failed: invalid size: len: %d", len);
		return FALSE;
	}
	dbg("get_interfaceinfo 0x%1x,0x%1x,0x%1x,0x%1x", intfinfo->bInterfaceClass,intfinfo->bInterfaceNumber,intfinfo->bInterfaceSubClass,intfinfo->bInterfaceProtocol);
	return TRUE;
}
BOOL build_interface(struct usbip_usb_device* pudev, struct usbip_usb_interface* pinterface, int idx)
{
	USB_INTERFACE_DESCRIPTOR intf_desc;
	//get_devconf(pudev->path, &intf_desc, idx);
	if (TRUE == get_devintf(pudev->path, &intf_desc, 0))
	{
		pinterface->bInterfaceClass = intf_desc.bInterfaceClass;
		pinterface->bInterfaceProtocol = intf_desc.bInterfaceProtocol;
		pinterface->bInterfaceSubClass = intf_desc.bInterfaceSubClass;
		
		return TRUE;
	}
	return FALSE;
}
BOOL build_compatible_id(struct usbip_usb_device* pudev, struct usbip_usb_interface* pinterface)
{
	pinterface->padding = 0;
	const char* devpath = pudev->path;
	dbg("build_compatible_id dev:%s", devpath);
	HANDLE	hdev;
	DWORD	len;
	hdev = CreateFile(pudev->path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (hdev == INVALID_HANDLE_VALUE) {
		dbg("build_compatible_id: cannot open device: %s", devpath);
		return FALSE;
	}
	ULONG size = 0;
	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_GET_COMPATIBLEIDS_SIZE, NULL, 0, &size, sizeof(ULONG), &len, NULL)) {
		dbg("build_compatible_id: DeviceIoControl IOCTL_USBIP_STUB_GET_COMPATIBLEIDS_SIZE failed: err: 0x%lx", GetLastError());
		CloseHandle(hdev);
		return FALSE;
	}
	char* ids = malloc(size);
	if (ids == NULL)
	{
		dbg("build_compatible_id: malloc failed");
		CloseHandle(hdev);
		return FALSE;
	}
	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_GET_COMPATIBLEIDS, NULL, 0, ids, size, &len, NULL))
	{
		dbg("build_compatible_id: DeviceIoControl IOCTL_USBIP_STUB_GET_COMPATIBLEIDS failed: err: 0x%lx", GetLastError());
		free(ids);
		CloseHandle(hdev);
		return FALSE;
	}
	BOOL ret = FALSE;
	const wchar_t* p = ids;
	while (*p != '\0' && (p - ids) < len - 1)
	{
		len = wcslen(p);
		if (len != 0)
		{
			wprintf(L"got compatible id :%s\n", p);
			if (swscanf(p, L"USB\\Class_%hhx&SubClass_%hhx&Prot_%hhx", &(pinterface->bInterfaceClass), &(pinterface->bInterfaceSubClass), &(pinterface->bInterfaceProtocol)) == 3)
			{
				ret = TRUE;
			}
			break;
		}
		p += (len + 1);
	};
	free(ids);
	dump_usb_interface(pinterface);
	CloseHandle(hdev);
	return ret;
}
BOOL
build_udev(devno_t devno, struct usbip_usb_device *pudev)
{
	char	*devpath;
	ioctl_usbip_stub_devinfo_t	Devinfo;

	devpath = get_devpath_from_devno(devno);
	if (devpath == NULL) {
		dbg("invalid devno: %hhu. devpath returned %s", devno, devpath);
		return FALSE;
	}

	memset(pudev, 0, sizeof(struct usbip_usb_device));

	pudev->busnum = 1;
	pudev->devnum = (int)devno;
	snprintf(pudev->path, USBIP_DEV_PATH_MAX, devpath);
	//打开设备,获取接口信息
	snprintf(pudev->busid, USBIP_BUS_ID_SIZE, "1-%hhu", devno);

	if (get_devinfo(devpath, &Devinfo)) {
		pudev->idVendor = Devinfo.vendor;
		pudev->idProduct = Devinfo.product;
		pudev->speed = Devinfo.speed;
		pudev->bDeviceClass = Devinfo.class;
		pudev->bDeviceSubClass = Devinfo.subclass;
		pudev->bDeviceProtocol = Devinfo.protocol;
	}
	free(devpath);

	return TRUE;
}

HANDLE
open_stub_dev(devno_t devno)
{
	HANDLE	hdev;
	char	*devpath;
	DWORD	len;

	devpath = get_devpath_from_devno(devno);
	if (devpath == NULL) {
		dbg("invalid devno: %hhu", devno);
		return INVALID_HANDLE_VALUE;
	}

	hdev = CreateFile(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	free(devpath);

	if (hdev == INVALID_HANDLE_VALUE) {
		dbg("cannot open device: %s", devpath);
		return INVALID_HANDLE_VALUE;
	}

	if (!DeviceIoControl(hdev, IOCTL_USBIP_STUB_EXPORT, NULL, 0, NULL, 0, &len, NULL)) {
		dbg("DeviceIoControl failed: err: 0x%lx", GetLastError());
		CloseHandle(hdev);
		return INVALID_HANDLE_VALUE;
	}
	return hdev;
}
