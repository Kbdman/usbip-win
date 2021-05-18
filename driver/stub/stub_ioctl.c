/* libusb-win32, Generic Windows USB Library
* Copyright (c) 2010 Travis Robinson <libusbdotnet@gmail.com>
* Copyright (c) 2002-2005 Stephan Meyer <ste_meyer@web.de>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "stub_driver.h"
#include "stub_dbg.h"
#include "stub_irp.h"
#include "usbip_stub_api.h"
#include "usbip_proto.h"

#include "stub_usbd.h"
#include "stub_devconf.h"

static UCHAR
get_speed_from_bcdUSB(USHORT bcdUSB)
{
	switch (bcdUSB) {
	case 0x0100:
		return USB_SPEED_LOW;
	case 0x0110:
		return USB_SPEED_FULL;
	case 0x0200:
		return USB_SPEED_HIGH;
	case 0x0250:
		return USB_SPEED_WIRELESS;
	case 0x0300:
		return USB_SPEED_SUPER;
	case 0x0310:
		return USB_SPEED_SUPER_PLUS;
	default:
		return USB_SPEED_UNKNOWN;
	}
}

static NTSTATUS
process_get_devinfo(usbip_stub_dev_t* devstub, IRP* irp)
{
	PIO_STACK_LOCATION	irpStack;
	ULONG	outlen;
	NTSTATUS	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	irp->IoStatus.Information = 0;
	if (outlen < sizeof(ioctl_usbip_stub_devinfo_t))
		status = STATUS_INVALID_PARAMETER;
	else {
		USB_DEVICE_DESCRIPTOR	desc;

		if (get_usb_device_desc(devstub, &desc)) {
			ioctl_usbip_stub_devinfo_t* devinfo;

			devinfo = (ioctl_usbip_stub_devinfo_t*)irp->AssociatedIrp.SystemBuffer;
			devinfo->vendor = desc.idVendor;
			devinfo->product = desc.idProduct;
			devinfo->speed = get_speed_from_bcdUSB(desc.bcdUSB);
			devinfo->class = desc.bDeviceClass;
			devinfo->subclass = desc.bDeviceSubClass;
			devinfo->protocol = desc.bDeviceProtocol;
			irp->IoStatus.Information = sizeof(ioctl_usbip_stub_devinfo_t);
		}
		else {
			status = STATUS_UNSUCCESSFUL;
		}
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}
static NTSTATUS
process_get_compatible_ids_size(usbip_stub_dev_t* devstub, IRP* irp)
{

	DBGI(DBG_IOCTL, "process_get_compatible_ids_size\n");
	PIO_STACK_LOCATION	irpStack;
	ULONG	outlen;
	NTSTATUS	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	irp->IoStatus.Information = 0;
	if (outlen < sizeof(ULONG))
	{
		DBGI(DBG_IOCTL, "process_get_compatible_ids_size bufsize too small size %d,%d needed\n", outlen, sizeof(ULONG));
		status = STATUS_INVALID_PARAMETER;
	}
	else
	{
		irp->IoStatus.Information = sizeof(ULONG);
		*((ULONG*)irp->AssociatedIrp.SystemBuffer) = devstub->ids_compatible_length;
		status = STATUS_SUCCESS;
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}
static NTSTATUS
process_get_compatible_ids(usbip_stub_dev_t* devstub, IRP* irp)
{

	DBGI(DBG_IOCTL, "process_get_compatible_ids\n");
	PIO_STACK_LOCATION	irpStack;
	ULONG	outlen;
	NTSTATUS	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	if (outlen < devstub->ids_compatible_length)
	{

		DBGI(DBG_IOCTL, "process_get_compatible_ids bufsize too small size %d,%d needed\n", outlen, devstub->ids_compatible_length);
		status = STATUS_INVALID_PARAMETER;
	}
	else
	{
		RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, devstub->ids_compatible, devstub->ids_compatible_length);
		irp->IoStatus.Information = devstub->ids_compatible_length;
		status = STATUS_SUCCESS;
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS
process_get_configinfo(usbip_stub_dev_t* devstub, IRP* irp)
{

	DBGI(DBG_IOCTL, "process_get_configinfo\n");
	PIO_STACK_LOCATION	irpStack;
	ULONG	outlen;
	NTSTATUS	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	irp->IoStatus.Information = 0;
	if (outlen < sizeof(USB_CONFIGURATION_DESCRIPTOR) || irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ioctl_usbip_index_param))
	{
		DBGI(DBG_IOCTL, "process_get_configinfo %d,%d,%d,%d \n", outlen, sizeof(USB_CONFIGURATION_DESCRIPTOR), irpStack->Parameters.DeviceIoControl.InputBufferLength, sizeof(ioctl_usbip_index_param));
		status = STATUS_INVALID_PARAMETER;
	}
	else {
		UCHAR idx = ((ioctl_usbip_index_param*)(irp->AssociatedIrp.SystemBuffer))->index;
		DBGI(DBG_IOCTL, "process_get_configinfo idx=%d \n", idx);
		PUSB_CONFIGURATION_DESCRIPTOR conf_desc= get_usb_dsc_conf(devstub,idx);
		if(conf_desc!=NULL){
			DBGI(DBG_IOCTL, "conf_desc=%p", conf_desc);
			RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, conf_desc, sizeof(USB_CONFIGURATION_DESCRIPTOR));
			ExFreePoolWithTag(conf_desc, USBIP_STUB_POOL_TAG);
			irp->IoStatus.Information = sizeof(USB_CONFIGURATION_DESCRIPTOR);
			DBGI(DBG_IOCTL, "free");
		}
		else {

			DBGE(DBG_IOCTL, "process_get_configinfo get_usb_dsc_conf == NULL \n");
			status = STATUS_UNSUCCESSFUL;
		}
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS
process_get_interfaceinfo(usbip_stub_dev_t* devstub, IRP* irp)
{

	DBGI(DBG_IOCTL, "process_get_interfaceinfo\n");
	PIO_STACK_LOCATION	irpStack;
	ULONG	outlen;
	NTSTATUS	status = STATUS_SUCCESS;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	outlen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	irp->IoStatus.Information = 0;
	if (outlen < sizeof(USB_CONFIGURATION_DESCRIPTOR) || irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ioctl_usbip_index_param))
	{
		DBGI(DBG_IOCTL, "process_get_interfaceinfo %d,%d,%d,%d \n", outlen, sizeof(USB_CONFIGURATION_DESCRIPTOR), irpStack->Parameters.DeviceIoControl.InputBufferLength, sizeof(ioctl_usbip_index_param));
		status = STATUS_INVALID_PARAMETER;
	}
	else {
		UCHAR idx = ((ioctl_usbip_index_param*)(irp->AssociatedIrp.SystemBuffer))->index;
		DBGI(DBG_IOCTL, "process_get_interfaceinfo idx=%d \n", idx);
		PUSB_CONFIGURATION_DESCRIPTOR conf_desc = get_usb_dsc_conf(devstub, 1);
		if (conf_desc != NULL) {
			DBGI(DBG_IOCTL, "process_get_interfaceinfo get_default config=%p", conf_desc);
			PUSB_INTERFACE_DESCRIPTOR intf_desc= dsc_find_intf(conf_desc, idx, 0);
			if (intf_desc == NULL)
			{
				DBGE(DBG_IOCTL, "process_get_interfaceinfo dsc_find_intf == NULL \n");
				status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, conf_desc, sizeof(USB_CONFIGURATION_DESCRIPTOR));
				ExFreePoolWithTag(conf_desc, USBIP_STUB_POOL_TAG);
				irp->IoStatus.Information = sizeof(USB_CONFIGURATION_DESCRIPTOR);
				DBGI(DBG_IOCTL, "free");
			}
		}
		else {

			DBGE(DBG_IOCTL, "process_get_interfaceinfo get_usb_dsc_conf == NULL \n");
			status = STATUS_UNSUCCESSFUL;
		}
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}


static NTSTATUS
process_export(usbip_stub_dev_t *devstub, IRP *irp)
{
	UNREFERENCED_PARAMETER(devstub);

	DBGI(DBG_IOCTL, "exporting: %s\n", dbg_devstub(devstub));

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DBGI(DBG_IOCTL, "exported: %s\n", dbg_devstub(devstub));

	return STATUS_SUCCESS;
}

NTSTATUS
stub_dispatch_ioctl(usbip_stub_dev_t *devstub, IRP *irp)
{
	PIO_STACK_LOCATION	irpStack;
	ULONG			ioctl_code;

	irpStack = IoGetCurrentIrpStackLocation(irp);
	ioctl_code = irpStack->Parameters.DeviceIoControl.IoControlCode;

	DBGI(DBG_IOCTL, "dispatch_ioctl: code: %s\n", dbg_stub_ioctl_code(ioctl_code));

	switch (ioctl_code) {
	case IOCTL_USBIP_STUB_GET_DEVINFO:
		return process_get_devinfo(devstub, irp);
	case IOCTL_USBIP_STUB_EXPORT:
		return process_export(devstub, irp);
	case IOCTL_USBIP_STUB_GET_INTERFACEINFO:
		return process_get_interfaceinfo(devstub, irp);
	case IOCTL_USBIP_STUB_GET_CONFIGINFO:
		return process_get_configinfo(devstub, irp);
	case IOCTL_USBIP_STUB_GET_COMPATIBLEIDS_SIZE:
		return process_get_compatible_ids_size(devstub, irp);;
	case IOCTL_USBIP_STUB_GET_COMPATIBLEIDS:
		return process_get_compatible_ids(devstub, irp);
	default:
		return pass_irp_down(devstub, irp, NULL, NULL);
	}
}
