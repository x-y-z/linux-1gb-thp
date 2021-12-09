/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 Intel Corporation */
#ifndef ADF_PFVF_VF_PROTO_H
#define ADF_PFVF_VF_PROTO_H

#include <linux/types.h>
#include "adf_accel_devices.h"

int adf_send_vf2pf_msg(struct adf_accel_dev *accel_dev, u32 msg);
int adf_send_vf2pf_req(struct adf_accel_dev *accel_dev, u32 msg, u32 *resp);

int adf_enable_vf2pf_comms(struct adf_accel_dev *accel_dev);

#endif /* ADF_PFVF_VF_PROTO_H */
