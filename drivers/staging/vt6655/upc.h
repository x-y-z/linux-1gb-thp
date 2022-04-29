/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 1996, 2003 VIA Networking Technologies, Inc.
 * All rights reserved.
 *
 * Purpose: Macros to access device
 *
 * Author: Tevin Chen
 *
 * Date: Mar 17, 1997
 *
 */

#ifndef __UPC_H__
#define __UPC_H__

#include "device.h"

/*---------------------  Export Definitions -------------------------*/

/* For memory mapped IO */

#define VNSvInPortW(dwIOAddress, pwData) \
	(*(pwData) = ioread16(dwIOAddress))

#define VNSvInPortD(dwIOAddress, pdwData) \
	(*(pdwData) = ioread32(dwIOAddress))

#define VNSvOutPortB(dwIOAddress, byData) \
	iowrite8((u8)(byData), dwIOAddress)

#define VNSvOutPortW(dwIOAddress, wData) \
	iowrite16((u16)(wData), dwIOAddress)

#define VNSvOutPortD(dwIOAddress, dwData) \
	iowrite32((u32)(dwData), dwIOAddress)

/*---------------------  Export Classes  ----------------------------*/

/*---------------------  Export Variables  --------------------------*/

/*---------------------  Export Functions  --------------------------*/

#endif /* __UPC_H__ */
