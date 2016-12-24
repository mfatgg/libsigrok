/*
 * This file is part of the sigrok project.
 *
 * Copyright (C) 2012-2016 mfatgg <mfatgg00@gmail.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef LIBSIGROK_HARDWARE_MINILA_MOCKUP_PROTOCOL_H
#define LIBSIGROK_HARDWARE_MINILA_MOCKUP_PROTOCOL_H

#include <glib.h>
#include <ftdi.h>
#include <stdint.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "minila_mockup"

#define USB_VENDOR_ID           0x0403
#define USB_DESCRIPTION         "miniLA USB Interface"
#define USB_VENDOR_NAME         "FTDI"
#define USB_MODEL_NAME          "Mockup"
#define USB_MODEL_VERSION       ""

#define NUM_PROBES              32
#define TRIGGER_TYPES           "01"
#define MIN_NUM_SAMPLES         1

#define SDRAM_SIZE              (4 * 512 * 1024)
#define BS                      4096 /* Block size */

#define BYTES_PER_SAMPLE        (((NUM_PROBES-1) / 8) + 1)
#define NUM_BLOCKS              (SDRAM_SIZE / BS) /* Number of blocks */
#define MAX_NUM_SAMPLES         (SDRAM_SIZE / BYTES_PER_SAMPLE)

enum {
    MINILA_MOCKUP,
};

struct minila_profile {
    int model;
    const char *modelname;
    const char *iproduct; /* USB iProduct string */
    unsigned int num_channels;
    uint64_t max_samplerate;
    const int num_trigger_matches;
    float trigger_constant;
};

/* Private, per-device-instance driver context. */
struct dev_context {
    /** Device profile struct for this device. */
    const struct minila_profile *prof;

    /** FTDI device context (used by libftdi). */
    struct ftdi_context *ftdic;

    /** The currently configured samplerate of the device. */
    uint64_t cur_samplerate;

    /** The current sampling limit (in ms). */
    uint64_t limit_msec;

    /** The current sampling limit (in number of samples). */
    uint64_t limit_samples;
    int limit_blocks;  // limit_samples*4 / BS

    /**
     * A buffer containing some samples from the device.
     * Format: Each sample is 4 byte, MSB of byte 3 is channel 31, LSB of byte 0 is channel 0.
     */
    uint8_t block_buf[BS];
    /**
     * Buffer containing all samples read from device
     */
    uint8_t *final_buf;

    /**
     * Trigger pattern (MSB = channel 7, LSB = channel 0).
     * A 1 bit matches a high signal, 0 matches a low signal on a probe.
     * Only low/high triggers (but not e.g. rising/falling) are supported.
     */
    uint8_t trigger_pattern;

    /**
     * Trigger mask (MSB = channel 7, LSB = channel 0).
     * A 1 bit means "must match trigger_pattern", 0 means "don't care".
     */
    uint8_t trigger_mask;

    /** Time (in seconds) before the trigger times out. */
    uint64_t trigger_timeout;

    /** Tells us whether an SR_DF_TRIGGER packet was already sent. */
    int trigger_found;

    /** Used for keeping track how much time has passed. */
    gint64 done;

    /** Counter/index for the data block to be read. */
    int block_counter;

    /** The samplerate index (selects the sample period) for the MINILA. */
    uint8_t samplerate_index;

    /** This MiniLa's USB PID (multiple versions exist). */
    uint16_t usb_vid;
    uint16_t usb_pid;

    /** Samplerates supported by this device. */
    uint64_t samplerates[32];
};

/* protocol.c */
extern SR_PRIV const char *minila_channel_names[];
extern const struct minila_profile minila_profiles[];
SR_PRIV void minila_fill_samplerates_if_needed(const struct sr_dev_inst *sdi);
SR_PRIV uint8_t minila_samplerate_to_divcount(const struct sr_dev_inst *sdi,
                                              uint64_t samplerate);
SR_PRIV int minila_write(struct dev_context *devc, uint8_t *buf, int size);
SR_PRIV int minila_convert_trigger(const struct sr_dev_inst *sdi);
SR_PRIV int minila_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate);
SR_PRIV int minila_read_block(struct dev_context *devc);
SR_PRIV void minila_send_block_to_session_bus(const struct sr_dev_inst *sdi, int block);

SR_PRIV uint8_t minila_samplerate_to_index(const struct sr_dev_inst *sdi, uint64_t samplerate);
SR_PRIV int minila_setup_and_run(struct dev_context *devc);
//SR_PRIV int minila_write_async(struct dev_context *devc, uint8_t *buf, int size);
//SR_PRIV void minila_async_complete(struct dev_context *devc, int wait_for_more);

#endif
