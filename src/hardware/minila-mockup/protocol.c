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

/*
 * TODO:
 *
 * - update for libftdi version 1.0 (see minila_write_async and minila_async_complete)
 * - verify with real hardware attached
 *
 * - verify received data with minila windows program + known hardware pattern on input
 * - separate WriteReg and ReadReg for FTDI
 * - use StatusRegister bits of MINILA
 * - correct sram read behavior (see uCommunication.pas -> ReadSRAM of orig minila source code)
 * - correct reset behavior (see dlgIO_USB.pas -> Sync_To_MPSSE of orig minila source code)
 * - triggers
 * - "done" timing for dev_context
 * - get rid of goto's
 * -
 * - fix vcd file writing? (32th channel wrong in gtkwave)
 * - more hwcaps support
 * - other minila versions (orig; other than 100 MHz)
 */

#include <config.h>
#include "protocol.h"

//  model, *modelname, *iproduct, num_channels, max_samplerate, num_trigger_matches, trigger_constant
SR_PRIV const struct minila_profile minila_profiles[] = {
  { MINILA_MOCKUP,  "MOCKUP",  "MiniLA Mockup",  32,  SR_MHZ(100), 2, 0.8388608 },
  ALL_ZERO
};

/* Channels are numbered 0-31. */
SR_PRIV const char *minila_channel_names[NUM_PROBES + 1] = {
    "0", "1", "2", "3", "4", "5", "6", "7",
    "8", "9", "10", "11", "12", "13", "14", "15",
    "16", "17", "18", "19", "20", "21", "22", "23",
    "24", "25", "26", "27", "28", "29", "30", "31",
    NULL,
};

// timebase divider coeficients for version 100MHz
/*
 * Min: 1 sample per 0.01us -> sample time is 0.084s, samplerate 100MHz
 * Max: 1 sample per 2.55us -> sample time is 21.391s, samplerate 392.15kHz
 */
SR_PRIV uint64_t minila_timebase_table_100[32] = {
          1,       2,       5,      10,      20,      50,
        100,     200,     500,    1000,    2000,    5000,
      10000,   20000,   50000,  100000,  200000,  500000,
    1000000, 2000000, 5000000,10000000,       2,       2,
          2,       2,       2,       2,       2,       2,
      2,       2
};

static int minila_close_usb_reset_sequencer(struct dev_context *devc);
SR_PRIV int minila_write_async(struct dev_context *devc, uint8_t *buf, int size);
SR_PRIV void minila_async_complete(struct dev_context *devc, int wait_for_more);


SR_PRIV void minila_fill_samplerates_if_needed(const struct sr_dev_inst *sdi)
{
    int i;
    struct dev_context *devc;

    devc = sdi->priv;

    /* Do nothing if supported_samplerates[] is already filled. */
    if (devc->samplerates[0] != 0)
        return;

    /* Fill supported_samplerates[] with the proper values. */
    for (i = 0; i < 32; i++)
        devc->samplerates[i] = SR_MHZ(100) /
            minila_timebase_table_100[i];
}


/**
 * Check if the given samplerate is supported by the MINILA hardware.
 *
 * @param samplerate The samplerate (in Hz) to check.
 * @return 1 if the samplerate is supported/valid, 0 otherwise.
 */
static int minila_is_valid_samplerate(const struct sr_dev_inst *sdi,
                    uint64_t samplerate)
{
    int i;
    struct dev_context *devc;

    devc = sdi->priv;

    minila_fill_samplerates_if_needed(sdi);

    for (i = 0; i < 32; i++) {
        if (devc->samplerates[i] == samplerate)
            return 1;
    }

    sr_err("Invalid samplerate (%" PRIu64 "Hz).", samplerate);

    return 0;
}


/**
 * Convert a samplerate (in Hz) to the 'divcount' value the MINILA wants.
 *
 * MINILA hardware: sample period = (divcount + 1) * 10ns.
 * Min. value for divcount: 0x00 (10ns sample period, 100MHz samplerate).
 * Max. value for divcount: 0xfe (2550ns sample period, 392.15kHz samplerate).
 *
 * @param sdi Device instance.
 * @param samplerate The samplerate in Hz.
 * @return The divcount value as needed by the hardware, or 0xff upon errors.
 */
SR_PRIV uint8_t minila_samplerate_to_index(const struct sr_dev_inst *sdi,
                                           uint64_t samplerate)
{
    int index = -1;
    int i;
    struct dev_context *devc;

    devc = sdi->priv;

    if (samplerate == 0) {
        sr_err("%s: samplerate was 0.", __func__);
        return 0xff;
    }

    for (i = 0; i < 32; i++) {
        if (devc->samplerates[i] == samplerate) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        sr_err("%s: Can't get divcount, samplerate invalid.", __func__);
        return 0xff;
    }

    return (uint8_t)index;
}


/**
 * Write data of a certain length to the MINILA's FTDI device.
 *
 * @param devc The struct containing private per-device-instance data. Must not
 *            be NULL. devc->ftdic must not be NULL either.
 * @param buf The buffer containing the data to write. Must not be NULL.
 * @param size The number of bytes to write. Must be >= 0.
 * @return The number of bytes written, or a negative value upon errors.
 */
SR_PRIV int minila_write(struct dev_context *devc, uint8_t *buf, int size)
{
    int bytes_written;

    /* Note: Caller checked that devc and devc->ftdic != NULL. */

    if (!buf) {
        sr_err("%s: buf was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (size < 0) {
        sr_err("%s: size was < 0.", __func__);
        return SR_ERR_ARG;
    }

    bytes_written = ftdi_write_data(devc->ftdic, buf, size);

    if (bytes_written < 0) {
        sr_err("%s: ftdi_write_data: (%d) %s.", __func__,
               bytes_written, ftdi_get_error_string(devc->ftdic));
        (void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
    } else if (bytes_written != size) {
        sr_err("%s: bytes to write: %d, bytes written: %d.",
               __func__, size, bytes_written);
        (void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
    }

    return bytes_written;
}


SR_PRIV int minila_write_async(struct dev_context *devc, uint8_t *buf, int size)
{
    int bytes_written = 0;

    /* Note: Caller checked that devc and devc->ftdic != NULL. */

    if (!buf) {
        sr_err("%s: buf was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (size < 0) {
        sr_err("%s: size was < 0.", __func__);
        return SR_ERR_ARG;
    }

    // TODO: port to libftdi 1.0
    //bytes_written = ftdi_write_data_async(devc->ftdic, buf, size);

    if (bytes_written < 0) {
        sr_err("%s: ftdi_write_data: (%d) %s.", __func__,
               bytes_written, ftdi_get_error_string(devc->ftdic));
        (void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
    } else if (bytes_written != size) {
        sr_err("%s: bytes to write: %d, bytes written: %d.",
               __func__, size, bytes_written);
        (void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
    }

    return bytes_written;
}


SR_PRIV void minila_async_complete(struct dev_context *devc, int wait_for_more)
{
    (void)devc;
    (void)wait_for_more;
    // TODO: port to libftdi 1.0
    //ftdi_async_complete(devc->ftdic, wait_for_more);
}


/**
 * Read a certain amount of bytes from the MINILA's FTDI device.
 *
 * @param devc The struct containing private per-device-instance data. Must not
 *            be NULL. devc->ftdic must not be NULL either.
 * @param buf The buffer where the received data will be stored. Must not
 *            be NULL.
 * @param size The number of bytes to read. Must be >= 1.
 * @return The number of bytes read, or a negative value upon errors.
 */
static int minila_read(struct dev_context *devc, uint8_t *buf, int size)
{
    int bytes_read;

    /* Note: Caller checked that devc and devc->ftdic != NULL. */

    if (!buf) {
        sr_err("%s: buf was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (size <= 0) {
        sr_err("%s: size was <= 0.", __func__);
        return SR_ERR_ARG;
    }

    bytes_read = ftdi_read_data(devc->ftdic, buf, size);

    if (bytes_read < 0) {
        sr_err("%s: ftdi_read_data: (%d) %s.", __func__,
               bytes_read, ftdi_get_error_string(devc->ftdic));
    } else if (bytes_read != size) {
        // sr_err("%s: Bytes to read: %d, bytes read: %d.",
        //        __func__, size, bytes_read);
    }

    return bytes_read;
}


/**
 * Close the MINILA USB port and reset the MINILA sequencer logic.
 *
 * @param devc The struct containing private per-device-instance data.
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments.
 */
static int minila_close_usb_reset_sequencer(struct dev_context *devc)
{
    /* Magic sequence of bytes for resetting the MINILA sequencer logic. */
    uint8_t buf[7] = {0x93, 0x00, 0x00, 0x40, 0x92, 0x00, 0x00};
    int ret;

    if (!devc) {
        sr_err("%s: devc was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (!devc->ftdic) {
        sr_err("%s: devc->ftdic was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (devc->ftdic->usb_dev) {
        /* Reset the MINILA sequencer logic, then wait 100ms. */
        sr_dbg("Resetting sequencer logic.");
        (void) minila_write(devc, buf, 7); /* Ignore errors. */
        g_usleep(100 * 1000);

        /* Purge FTDI buffers, then reset and close the FTDI device. */
        sr_dbg("Purging buffers, resetting+closing FTDI device.");

        /* Log errors, but ignore them (i.e., don't abort). */
        if ((ret = ftdi_usb_purge_buffers(devc->ftdic)) < 0)
            sr_err("%s: ftdi_usb_purge_buffers: (%d) %s.",
                __func__, ret, ftdi_get_error_string(devc->ftdic));
        if ((ret = ftdi_usb_reset(devc->ftdic)) < 0)
            sr_err("%s: ftdi_usb_reset: (%d) %s.", __func__,
                   ret, ftdi_get_error_string(devc->ftdic));
        if ((ret = ftdi_usb_close(devc->ftdic)) < 0)
            sr_err("%s: ftdi_usb_close: (%d) %s.", __func__,
                   ret, ftdi_get_error_string(devc->ftdic));
    }

    /* Close USB device, deinitialize and free the FTDI context. */
    ftdi_free(devc->ftdic); /* Returns void. */
    devc->ftdic = NULL;

    return SR_OK;
}


/**
 * Reset the MINILA.
 *
 * The MINILA must be reset after a failed read/write operation or upon timeouts.
 *
 * @param devc The struct containing private per-device-instance data.
 * @return SR_OK upon success, SR_ERR upon failure.
 */
static int minila_reset(struct dev_context *devc)
{
    uint8_t buf[BS];
    gint64 done, now;
    int bytes_read;

    if (!devc) {
        sr_err("%s: devc was NULL.", __func__);
        return SR_ERR_ARG;
    }

    if (!devc->ftdic) {
        sr_err("%s: devc->ftdic was NULL.", __func__);
        return SR_ERR_ARG;
    }

    sr_dbg("Resetting the device.");

    /*
     * Purge pending read data from the FTDI hardware FIFO until
     * no more data is left, or a timeout occurs (after 20s).
     */
    done = (20 * G_TIME_SPAN_SECOND) + g_get_monotonic_time();
    do {
        /* Try to read bytes until none are left (or errors occur). */
        bytes_read = minila_read(devc, (uint8_t *)&buf, BS);
        now = g_get_monotonic_time();
    } while ((done > now) && (bytes_read > 0));

    /* Reset the MINILA sequencer logic and close the USB port. */
    (void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */

    sr_dbg("Device reset finished.");

    return SR_OK;
}


SR_PRIV int minila_convert_trigger(const struct sr_dev_inst *sdi)
{
    struct dev_context *devc;
    struct sr_trigger *trigger;
    struct sr_trigger_stage *stage;
    struct sr_trigger_match *match;
    const GSList *l, *m;
    uint16_t channel_bit;

    devc = sdi->priv;
    devc->trigger_pattern = 0x0000; /* Default to "low" trigger. */
    devc->trigger_mask = 0x0000; /* Default to "don't care". */

    sr_dbg("entering minila_configure_probes");

    if (!(trigger = sr_session_trigger_get(sdi->session)))
        return SR_OK;

    if (g_slist_length(trigger->stages) > 1) {
        sr_err("This device only supports 1 trigger stage.");
        return SR_ERR;
    }

    for (l = trigger->stages; l; l = l->next) {
        stage = l->data;
        for (m = stage->matches; m; m = m->next) {
            match = m->data;
            if (!match->channel->enabled)
                /* Ignore disabled channels with a trigger. */
                continue;
            if ((match->match == SR_TRIGGER_RISING) ||
                    (match->match == SR_TRIGGER_FALLING)) {
                sr_err("This model supports only simple triggers.");
                return SR_ERR;
            }
            channel_bit = (1 << (match->channel->index));

            /* state: 1 == high. */
            if (match->match == SR_TRIGGER_ONE)
                devc->trigger_pattern |= channel_bit;

        }
    }

    sr_dbg("Trigger pattern/mask = 0x%04x / 0x%04x.",
            devc->trigger_pattern, devc->trigger_mask);

    return SR_OK;
}


SR_PRIV int minila_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate)
{
    struct dev_context *devc;

    /* Note: Caller checked that sdi and sdi->priv != NULL. */

    devc = sdi->priv;

    sr_spew("Trying to set samplerate to %" PRIu64 "Hz.", samplerate);

    minila_fill_samplerates_if_needed(sdi);

    /* Check if this is a samplerate supported by the hardware. */
    if (!minila_is_valid_samplerate(sdi, samplerate))
        sr_dbg("Failed to set invalid samplerate (%" PRIu64 "Hz).",
               samplerate);
        return SR_ERR;

    /* Set the new samplerate. */
    devc->cur_samplerate = samplerate;

    sr_dbg("Samplerate set to %" PRIu64 "Hz.", devc->cur_samplerate);

    return SR_OK;
}


/**
 * Get a block of data from the MINILA.
 *
 * @param devc The struct containing private per-device-instance data. Must not
 *            be NULL. devc->ftdic must not be NULL either.
 * @return SR_OK upon success, or SR_ERR upon errors.
 */
SR_PRIV int minila_read_block(struct dev_context *devc)
{
    int i, bytes_read, bytes_written;
    gint64 now;
    static uint8_t buf[1 + 2*BS + 1];

    /* Note: Caller checked that devc and devc->ftdic != NULL. */

    sr_spew("Reading block %d.", devc->block_counter);


    //bytes_read = minila_read(devc, devc->mangled_buf, BS);

    /* If first block read got 0 bytes, retry until success or timeout. */
    //if ((bytes_read == 0) && (devc->block_counter == 0)) {
    if (devc->block_counter == 0) {
        sr_dbg("block_counter = %d", devc->block_counter);
        do {
            /* Read status register 2 */
            buf[0] = 0x91;  // CPUMode Read Extended Address
            buf[1] = 0x01;  // addr_high = 1 to switch from writing to reading
            buf[2] = 0x03;  // addr_low = status register 2
            buf[3] = 0x87;  // immediate read return value
            bytes_written = minila_write(devc, buf, 4);
            if (bytes_written != 4) {
                sr_err("Acquisition failed to start: %d.", bytes_written);
                return SR_ERR;
            }
            do {
                bytes_read = minila_read(devc, buf, 1);
                now = time(NULL);
            } while ((devc->done > now) && (bytes_read == 0));
            sr_dbg("MINILA Status register 2: 0x%02x", buf[0]);

            /* Write command: enable autoincrement */
            if (buf[0] & 0x80) {
                buf[0] = 0x93;
                buf[1] = 0x00;
                buf[2] = 0x00;
                buf[3] = 0x10;
                bytes_written = minila_write(devc, buf, 4);
            }

            //sr_spew("Reading block 0 (again).");
            //bytes_read = minila_read(devc, devc->mangled_buf, BS);
            /* TODO: How to handle read errors here? */
            //now = time(NULL);
        } while ((devc->done > now) && !(buf[0] & 0x80));

        buf[0] = 0x91;  // CPUMode Read Extended Address
        buf[1] = 0x01;  // addr_high = 1 to switch from writing to reading
        buf[2] = 0x00;  // addr_low = data register
        for (i=1; i<BS; i++) {
            /* Read 32-bit (1 dataword) of sampled data */
            buf[1 + 2*i] = 0x90;
            buf[1 + 2*i + 1] = 0x00;
        }
        buf[1 + 2*BS] = 0x87;

    }

    bytes_written = minila_write_async(devc, buf, 1 + 2*BS + 1);
    //sr_dbg("bytes written: %d", bytes_written);

    do {
        bytes_read = minila_read(devc, devc->block_buf, BS);
        now = time(NULL);
    } while ((devc->done > now) && (bytes_read == 0));
    //sr_dbg("bytes read: %d", bytes_read_total);

    minila_async_complete(devc, 0);

    /* Check if block read was successful or a timeout occured. */
    if (bytes_read != BS) {
        sr_err("Trigger timed out. Bytes read: %d.", bytes_read);
        (void) minila_reset(devc); /* Ignore errors. */
        return SR_ERR;
    }

    /* create final buffer with all sampled data */
    memcpy(devc->final_buf + (devc->block_counter * BS), devc->block_buf, BS);

    return SR_OK;
}


SR_PRIV void minila_send_block_to_session_bus(const struct sr_dev_inst *sdi, int block)
{
//  int i;
//  uint8_t sample, expected_sample;
    struct sr_datafeed_packet packet;
    struct sr_datafeed_logic logic;
    int trigger_point; /* Relative trigger point (in this block). */
    struct dev_context *devc;

    /* Note: Caller ensures devc/devc->ftdic != NULL and block > 0. */

    devc = sdi->priv;

    /* Check if we can find the trigger condition in this block. */
    trigger_point = -1;
//  expected_sample = devc->trigger_pattern & devc->trigger_mask;
//  for (i = 0; i < BS; i++) {
//      /* Don't continue if the trigger was found previously. */
//      if (devc->trigger_found)
//          break;
//
//      /*
//       * Also, don't continue if triggers are "don't care", i.e. if
//       * no trigger conditions were specified by the user. In that
//       * case we don't want to send an SR_DF_TRIGGER packet at all.
//       */
//      if (devc->trigger_mask == 0x00)
//          break;
//
//      sample = *(devc->final_buf + (block * BS) + i);
//
//      if ((sample & devc->trigger_mask) == expected_sample) {
//          trigger_point = i;
//          devc->trigger_found = 1;
//          break;
//      }
//  }

    /* If no trigger was found, send one SR_DF_LOGIC packet. */
    if (trigger_point == -1) {
        /* Send an SR_DF_LOGIC packet to the session bus. */
        sr_spew("Sending SR_DF_LOGIC packet (%d bytes) for "
                "block %d.", BS, block);
        packet.type = SR_DF_LOGIC;
        packet.payload = &logic;
        /* last block? */
        if (block == (devc->limit_blocks - 1)) {
            logic.length = (devc->limit_samples * BYTES_PER_SAMPLE) % BS;
            if (logic.length == 0) {
                logic.length = BS;
            }
        } else {
            logic.length = BS;
        }
        sr_dbg("length = %" PRIu64 "", logic.length);
        logic.unitsize = BYTES_PER_SAMPLE;
        sr_dbg("unitsize = %d", logic.unitsize);
        logic.data = devc->final_buf + (block * BS);
        sr_session_send(sdi, &packet);
        return;
    }

    /*
     * We found the trigger, so some special handling is needed. We have
     * to send an SR_DF_LOGIC packet with the samples before the trigger
     * (if any), then the SD_DF_TRIGGER packet itself, then another
     * SR_DF_LOGIC packet with the samples after the trigger (if any).
     */

    /* TODO: Send SR_DF_TRIGGER packet before or after the actual sample? */

//  /* If at least one sample is located before the trigger... */
//  if (trigger_point > 0) {
//      /* Send pre-trigger SR_DF_LOGIC packet to the session bus. */
//      sr_spew("Sending pre-trigger SR_DF_LOGIC packet, "
//          "start = %d, length = %d.", block * BS, trigger_point);
//      packet.type = SR_DF_LOGIC;
//      packet.payload = &logic;
//      logic.length = trigger_point;
//      logic.unitsize = 1;
//      logic.data = devc->final_buf;
//      sr_session_send(sdi, &packet);
//  }

//  /* Send the SR_DF_TRIGGER packet to the session bus. */
//  sr_spew("Sending SR_DF_TRIGGER packet, sample = %d.",
//      (block * BS) + trigger_point);
//  packet.type = SR_DF_TRIGGER;
//  packet.payload = NULL;
//  sr_session_send(sdi, &packet);

//  /* If at least one sample is located after the trigger... */
//  if (trigger_point < (BS - 1)) {
//      /* Send post-trigger SR_DF_LOGIC packet to the session bus. */
//      sr_spew("Sending post-trigger SR_DF_LOGIC packet, "
//          "start = %d, length = %d.",
//          (block * BS) + trigger_point, BS - trigger_point);
//      packet.type = SR_DF_LOGIC;
//      packet.payload = &logic;
//      logic.length = BS - trigger_point;
//      logic.unitsize = 1;
//      logic.data = devc->final_buf + trigger_point;
//      sr_session_send(sdi, &packet);
//  }
}


SR_PRIV int minila_setup_and_run(struct dev_context *devc)
{
    uint8_t buf[128];
    int bytes_written, bytes_read;
    gint64 done, now;

    /* Reset command */
    buf[0] = 0x93;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x40;
    /* Trigger events counter command */
    buf[4] = 0x92;
    buf[5] = 0x01;
    buf[6] = 0x00;  // 1 trigger hit
    /* Trigger length counter command */
    buf[7] = 0x92;
    buf[8] = 0x02;
    buf[9] = 0x01;  // min. trigger length = 1 clk
    /* Timebase command (Timeanalysis firmware only) */
    buf[10] = 0x92;
    buf[11] = 0x03;
    buf[12] = devc->samplerate_index;  // samplerate select
    sr_dbg("MINILA Samplerate select: %d", devc->samplerate_index);
    /* Trigger pre/post command */
    buf[13] = 0x92;
    buf[14] = 0x04;
    buf[15] = 0x1f;  // no pretrigger, 512k posttrigger
    /* Trigger value x7:x0 command */
    buf[16] = 0x92;
    buf[17] = 0x05;
    buf[18] = 0x00;  // compare inputs with 0x00
    /* Trigger value x15:x8 command */
    buf[19] = 0x92;
    buf[20] = 0x06;
    buf[21] = 0x00;  // compare inputs with 0x00
    /* Trigger edge e15:e8 command */
    buf[22] = 0x92;
    buf[23] = 0x07;
    buf[24] = 0x00;  // compare inputs with using value (not edge)
    /* Trigger edge e7:e0 command */
    buf[25] = 0x92;
    buf[26] = 0x08;
    buf[27] = 0x00;  // compare inputs with using value (not edge)
    /* Trigger mask m15:m8 command */
    buf[28] = 0x92;
    buf[29] = 0x09;
    buf[30] = 0x00;  // ignore all input bits
    /* Trigger mask m7:m0 command */
    buf[31] = 0x92;
    buf[32] = 0x0a;
    buf[33] = 0x00;  // ignore all input bits
    /* Trigger control command */
    buf[34] = 0x92;
    buf[35] = 0x0d;
    buf[36] = 0x00;  // use internal trigger, do not invert trigger
    bytes_written = minila_write(devc, buf, 37);
    if (bytes_written != 37) {
        sr_err("Acquisition failed to start: %d.", bytes_written);
        return SR_ERR;
    }

    /* Read status register 1 & 2 */
    buf[0] = 0x91;  // CPUMode Read Extended Address
    buf[1] = 0x01;  // addr_high = 1 to switch from writing to reading
    buf[2] = 0x01;  // addr_low = status register 1
    buf[3] = 0x90;  // CPUMode Read Short Address
    buf[4] = 0x03;  // addr_low = status register 2
    buf[5] = 0x87;  // immediate read return value
    bytes_written = minila_write(devc, buf, 6);
    if (bytes_written != 6) {
        sr_err("Acquisition failed to start: %d.", bytes_written);
        return SR_ERR;
    }

    // Timeout = 1s
    done = 1 + time(NULL);
    do {
        bytes_read = minila_read(devc, buf, 2);
        now = time(NULL);
    } while ((done > now) && (bytes_read == 0));

    sr_dbg("MINILA Status register 1: 0x%02x", buf[0]);
    sr_dbg("MINILA Status register 2: 0x%02x", buf[1]);


    /* Run command */
    buf[0] = 0x93;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x80;
    bytes_written = minila_write(devc, buf, 4);
    if (bytes_written != 4) {
        sr_err("Acquisition failed to start: %d.", bytes_written);
        return SR_ERR;
    }

    return SR_OK;
}
