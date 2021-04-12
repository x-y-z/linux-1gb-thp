/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 *
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *
 ******************************************************************************/
#ifndef __USB_OPS_LINUX_H__
#define __USB_OPS_LINUX_H__

#define USB_HIGH_SPEED_BULK_SIZE	512
#define USB_FULL_SPEED_BULK_SIZE	64

#define usb_write_port_complete(purb, regs)		\
	usb_write_port_complete(purb)
#define usb_read_port_complete(purb, regs)		\
	usb_read_port_complete(purb)

unsigned int ffaddr2pipehdl(struct dvobj_priv *pdvobj, u32 addr);

u8 usb_read8(struct adapter *adapter, u32 addr);
u16 usb_read16(struct adapter *adapter, u32 addr);
u32 usb_read32(struct adapter *adapter, u32 addr);

u32 usb_read_port(struct adapter *adapter, u32 addr, struct recv_buf *precvbuf);
void usb_read_port_cancel(struct adapter *adapter);

int usb_write8(struct adapter *adapter, u32 addr, u8 val);
int usb_write16(struct adapter *adapter, u32 addr, u16 val);
int usb_write32(struct adapter *adapter, u32 addr, u32 val);

u32 usb_write_port(struct adapter *adapter, u32 addr, u32 cnt, struct xmit_buf *pmem);
void usb_write_port_cancel(struct adapter *adapter);

#endif
