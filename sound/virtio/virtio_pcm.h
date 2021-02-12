/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * virtio-snd: Virtio sound device
 * Copyright (C) 2021 OpenSynergy GmbH
 */
#ifndef VIRTIO_SND_PCM_H
#define VIRTIO_SND_PCM_H

#include <linux/atomic.h>
#include <linux/virtio_config.h>
#include <sound/pcm.h>

struct virtio_pcm;
struct virtio_pcm_msg;

/**
 * struct virtio_pcm_substream - VirtIO PCM substream.
 * @snd: VirtIO sound device.
 * @nid: Function group node identifier.
 * @sid: Stream identifier.
 * @direction: Stream data flow direction (SNDRV_PCM_STREAM_XXX).
 * @features: Stream VirtIO feature bit map (1 << VIRTIO_SND_PCM_F_XXX).
 * @substream: Kernel ALSA substream.
 * @hw: Kernel ALSA substream hardware descriptor.
 * @frame_bytes: Current frame size in bytes.
 * @period_size: Current period size in frames.
 * @buffer_size: Current buffer size in frames.
 * @lock: Spinlock that protects fields shared by interrupt handlers and
 *        substream operators.
 * @hw_ptr: Substream hardware pointer value in frames [0 ... buffer_size).
 * @xfer_enabled: Data transfer state (0 - off, 1 - on).
 * @xfer_xrun: Data underflow/overflow state (0 - no xrun, 1 - xrun).
 * @msgs: Allocated I/O messages.
 * @nmsgs: Number of allocated I/O messages.
 * @msg_last_enqueued: Index of the last I/O message added to the virtqueue.
 * @msg_count: Number of pending I/O messages in the virtqueue.
 * @msg_empty: Notify when msg_count is zero.
 * @msg_flushing: True if the I/O queue is in flushing state.
 */
struct virtio_pcm_substream {
	struct virtio_snd *snd;
	unsigned int nid;
	unsigned int sid;
	u32 direction;
	u32 features;
	struct snd_pcm_substream *substream;
	struct snd_pcm_hardware hw;
	unsigned int frame_bytes;
	snd_pcm_uframes_t period_size;
	snd_pcm_uframes_t buffer_size;
	spinlock_t lock;
	snd_pcm_uframes_t hw_ptr;
	bool xfer_enabled;
	bool xfer_xrun;
	struct virtio_pcm_msg **msgs;
	unsigned int nmsgs;
	int msg_last_enqueued;
	unsigned int msg_count;
	wait_queue_head_t msg_empty;
	bool msg_flushing;
};

/**
 * struct virtio_pcm_stream - VirtIO PCM stream.
 * @substreams: VirtIO substreams belonging to the stream.
 * @nsubstreams: Number of substreams.
 * @chmaps: Kernel channel maps belonging to the stream.
 * @nchmaps: Number of channel maps.
 */
struct virtio_pcm_stream {
	struct virtio_pcm_substream **substreams;
	unsigned int nsubstreams;
	struct snd_pcm_chmap_elem *chmaps;
	unsigned int nchmaps;
};

/**
 * struct virtio_pcm - VirtIO PCM device.
 * @list: VirtIO PCM list entry.
 * @nid: Function group node identifier.
 * @pcm: Kernel PCM device.
 * @streams: VirtIO PCM streams (playback and capture).
 */
struct virtio_pcm {
	struct list_head list;
	unsigned int nid;
	struct snd_pcm *pcm;
	struct virtio_pcm_stream streams[SNDRV_PCM_STREAM_LAST + 1];
};

extern const struct snd_pcm_ops virtsnd_pcm_ops;

int virtsnd_pcm_validate(struct virtio_device *vdev);

int virtsnd_pcm_parse_cfg(struct virtio_snd *snd);

int virtsnd_pcm_build_devs(struct virtio_snd *snd);

void virtsnd_pcm_event(struct virtio_snd *snd, struct virtio_snd_event *event);

void virtsnd_pcm_tx_notify_cb(struct virtqueue *vqueue);

void virtsnd_pcm_rx_notify_cb(struct virtqueue *vqueue);

struct virtio_pcm *virtsnd_pcm_find(struct virtio_snd *snd, unsigned int nid);

struct virtio_pcm *virtsnd_pcm_find_or_create(struct virtio_snd *snd,
					      unsigned int nid);

struct virtio_snd_msg *
virtsnd_pcm_ctl_msg_alloc(struct virtio_pcm_substream *vss,
			  unsigned int command, gfp_t gfp);

int virtsnd_pcm_msg_alloc(struct virtio_pcm_substream *vss,
			  unsigned int periods, unsigned int period_bytes);

void virtsnd_pcm_msg_free(struct virtio_pcm_substream *vss);

int virtsnd_pcm_msg_send(struct virtio_pcm_substream *vss);

#endif /* VIRTIO_SND_PCM_H */
