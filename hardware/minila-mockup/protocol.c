/*
 * This file is part of the sigrok project.
 *
 * Copyright (C) 2012 mfatgg <mfatgg00@gmail.com>
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

#include <ftdi.h>
#include <glib.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"
#include "protocol.h"

/* Probes are numbered 0-31. */
SR_PRIV const char *minila_probe_names[NUM_PROBES + 1] = {
	"0", "1", "2", "3", "4", "5", "6", "7",
	"8", "9", "10", "11", "12", "13", "14", "15",
	"16", "17", "18", "19", "20", "21", "22", "23",
	"24", "25", "26", "27", "28", "29", "30", "31",
	NULL,
};

   // timebase divider coeficients for version 100MHz
SR_PRIV uint64_t minila_timebase_table_100[32] = {
          1,       2,       5,      10,      20,      50,
        100,     200,     500,    1000,    2000,    5000,
      10000,   20000,   50000,  100000,  200000,  500000,
    1000000, 2000000, 5000000,10000000,       2,       2,
          2, 	   2,       2,       2,       2,       2,
	  2,       2
};

/* This will be initialized via hw_info_get()/SR_DI_SAMPLERATES. */
SR_PRIV uint64_t minila_supported_samplerates[33] = { 0 };

/*
 * Min: 1 sample per 0.01us -> sample time is 0.084s, samplerate 100MHz
 * Max: 1 sample per 2.55us -> sample time is 21.391s, samplerate 392.15kHz
 */
const struct sr_samplerates minila_samplerates = {
	.low  = 0,
	.high = 0,
	.step = 0,
	.list = minila_supported_samplerates,
};

/* Note: Continuous sampling is not supported by the hardware. */
SR_PRIV const int minila_hwcaps[] = {
	SR_HWCAP_LOGIC_ANALYZER,
	SR_HWCAP_SAMPLERATE,
	SR_HWCAP_LIMIT_MSEC, /* TODO: Not yet implemented. */
	SR_HWCAP_LIMIT_SAMPLES,
	0,
};

SR_PRIV void minila_fill_supported_samplerates_if_needed(void)
{
	int i;

	/* Do nothing if supported_samplerates[] is already filled. */
	if (minila_supported_samplerates[0] != 0)
		return;

	/* Fill supported_samplerates[] with the proper values. */
	for (i = 0; i < 32; i++)
		minila_supported_samplerates[i] = SR_MHZ(100) /
			minila_timebase_table_100[i];
}

/**
 * Check if the given samplerate is supported by the MINILA hardware.
 *
 * @param samplerate The samplerate (in Hz) to check.
 * @return 1 if the samplerate is supported/valid, 0 otherwise.
 */
SR_PRIV int minila_is_valid_samplerate(uint64_t samplerate)
{
	int i;

	minila_fill_supported_samplerates_if_needed();

	for (i = 0; i < 32; i++) {
		if (minila_supported_samplerates[i] == samplerate)
			return i;
	}

	sr_err("Invalid samplerate (%" PRIu64 "Hz).", samplerate);

	return -1;
}

/**
 * Convert a samplerate (in Hz) to the 'divcount' value the MINILA wants.
 *
 * MINILA hardware: sample period = (divcount + 1) * 10ns.
 * Min. value for divcount: 0x00 (10ns sample period, 100MHz samplerate).
 * Max. value for divcount: 0xfe (2550ns sample period, 392.15kHz samplerate).
 *
 * @param samplerate The samplerate in Hz.
 * @return The divcount value as needed by the hardware, or 0xff upon errors.
 */
SR_PRIV uint8_t minila_samplerate_to_index(uint64_t samplerate)
{
	int index;

	if (samplerate == 0) {
		sr_err("%s: samplerate was 0.", __func__);
		return 0xff;
	}

	index = minila_is_valid_samplerate(samplerate);
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

	bytes_written = ftdi_write_data_async(devc->ftdic, buf, size);

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
	ftdi_async_complete(devc->ftdic, wait_for_more);
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
SR_PRIV int minila_read(struct dev_context *devc, uint8_t *buf, int size)
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

SR_PRIV int minila_close(struct dev_context *devc)
{
	int ret;

	if (!devc) {
		sr_err("%s: devc was NULL.", __func__);
		return SR_ERR_ARG;
	}

	if (!devc->ftdic) {
		sr_err("%s: devc->ftdic was NULL.", __func__);
		return SR_ERR_ARG;
	}

	if ((ret = ftdi_usb_close(devc->ftdic)) < 0) {
		sr_err("%s: ftdi_usb_close: (%d) %s.",
		       __func__, ret, ftdi_get_error_string(devc->ftdic));
	}

	return ret;
}

/**
 * Close the MINILA USB port and reset the MINILA sequencer logic.
 *
 * @param devc The struct containing private per-device-instance data.
 * @return SR_OK upon success, SR_ERR_ARG upon invalid arguments.
 */
SR_PRIV int minila_close_usb_reset_sequencer(struct dev_context *devc)
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
SR_PRIV int minila_reset(struct dev_context *devc)
{
	uint8_t buf[BS];
	time_t done, now;
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
	done = 20 + time(NULL);
	do {
		/* TODO: Ignore errors? Check for < 0 at least! */
		bytes_read = minila_read(devc, (uint8_t *)&buf, BS);
		now = time(NULL);
	} while ((done > now) && (bytes_read > 0));

	/* Reset the MINILA sequencer logic and close the USB port. */
	(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */

	sr_dbg("Device reset finished.");

	return SR_OK;
}

SR_PRIV int minila_configure_probes(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	const struct sr_probe *probe;
	const GSList *l;
	uint8_t probe_bit;
	char *tc;

	devc = sdi->priv;
	devc->trigger_pattern = 0;
	devc->trigger_mask = 0; /* Default to "don't care" for all probes. */

	sr_dbg("entering minila_configure_probes");

	for (l = sdi->probes; l; l = l->next) {
		probe = (struct sr_probe *)l->data;

		if (!probe) {
			sr_err("%s: probe was NULL.", __func__);
			return SR_ERR;
		}

		/* Skip disabled probes. */
		if (!probe->enabled)
			continue;

		/* Skip (enabled) probes with no configured trigger. */
		if (!probe->trigger)
			continue;

		/* Note: Must only be run if probe->trigger != NULL. */
		if (probe->index < 0 || probe->index > 7) {
			sr_err("%s: Invalid probe index %d, must be "
			       "between 0 and 7.", __func__, probe->index);
			return SR_ERR;
		}

		probe_bit = (1 << (probe->index));

		/* Configure the probe's trigger mask and trigger pattern. */
		for (tc = probe->trigger; tc && *tc; tc++) {
			devc->trigger_mask |= probe_bit;

			/* Sanity check, MINILA only supports low/high trigger. */
			if (*tc != '0' && *tc != '1') {
				sr_err("%s: Invalid trigger '%c', only "
				       "'0'/'1' supported.", __func__, *tc);
				return SR_ERR;
			}

			if (*tc == '1')
				devc->trigger_pattern |= probe_bit;
		}
	}

	sr_dbg("Trigger mask = 0x%x, trigger pattern = 0x%x.",
	       devc->trigger_mask, devc->trigger_pattern);

	return SR_OK;
}

SR_PRIV int minila_set_samplerate(const struct sr_dev_inst *sdi, uint64_t samplerate)
{
	struct dev_context *devc;

	/* Note: Caller checked that sdi and sdi->priv != NULL. */

	devc = sdi->priv;

	sr_spew("Trying to set samplerate to %" PRIu64 "Hz.", samplerate);

	minila_fill_supported_samplerates_if_needed();

	/* Check if this is a samplerate supported by the hardware. */
	if (!minila_is_valid_samplerate(samplerate))
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
	int i, j, byte_offset, m, mi, p, index, bytes_read, bytes_written;
	int bytes_remaining, bytes_read_total, ret;
	time_t now;
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

	// read chunks of 256 bytes
	bytes_read_total = 0;

	bytes_written = minila_write_async(devc, buf, 1 + 2*BS + 1);
	//sr_dbg("bytes written: %d", bytes_written);

	bytes_remaining = BS;
	do {
		bytes_read = minila_read(devc, &devc->block_buf[j], bytes_remaining);
		bytes_remaining -= bytes_read;
		bytes_read_total += bytes_read;
		now = time(NULL);
	} while ((devc->done > now) && (bytes_remaining > 0));
	//sr_dbg("bytes read: %d", bytes_read_total);

	minila_async_complete(devc, 0);

	/* Check if block read was successful or a timeout occured. */
	if (bytes_read_total != BS) {
		sr_err("Trigger timed out. Bytes read: %d.", bytes_read_total);
		(void) minila_reset(devc); /* Ignore errors. */
		return SR_ERR;
	}

	/* create final buffer with all sampled data */
	memcpy(devc->final_buf + (devc->block_counter * BS), devc->block_buf, BS);

	return SR_OK;
}

SR_PRIV void minila_send_block_to_session_bus(struct dev_context *devc, int block)
{
	int i;
	uint8_t sample, expected_sample;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;
	int trigger_point; /* Relative trigger point (in this block). */

	/* Note: No sanity checks on devc/block, caller is responsible. */

	/* Check if we can find the trigger condition in this block. */
	trigger_point = -1;
//	expected_sample = devc->trigger_pattern & devc->trigger_mask;
//	for (i = 0; i < BS; i++) {
//		/* Don't continue if the trigger was found previously. */
//		if (devc->trigger_found)
//			break;
//
//		/*
//		 * Also, don't continue if triggers are "don't care", i.e. if
//		 * no trigger conditions were specified by the user. In that
//		 * case we don't want to send an SR_DF_TRIGGER packet at all.
//		 */
//		if (devc->trigger_mask == 0x00)
//			break;
//
//		sample = *(devc->final_buf + (block * BS) + i);
//
//		if ((sample & devc->trigger_mask) == expected_sample) {
//			trigger_point = i;
//			devc->trigger_found = 1;
//			break;
//		}
//	}

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
		sr_dbg("length = %d", logic.length);
		logic.unitsize = BYTES_PER_SAMPLE;
		sr_dbg("unitsize = %d", logic.unitsize);
		logic.data = devc->final_buf + (block * BS);
		sr_session_send(devc->session_dev_id, &packet);
		return;
	}

	/*
	 * We found the trigger, so some special handling is needed. We have
	 * to send an SR_DF_LOGIC packet with the samples before the trigger
	 * (if any), then the SD_DF_TRIGGER packet itself, then another
	 * SR_DF_LOGIC packet with the samples after the trigger (if any).
	 */

	/* TODO: Send SR_DF_TRIGGER packet before or after the actual sample? */

//	/* If at least one sample is located before the trigger... */
//	if (trigger_point > 0) {
//		/* Send pre-trigger SR_DF_LOGIC packet to the session bus. */
//		sr_spew("Sending pre-trigger SR_DF_LOGIC packet, "
//			"start = %d, length = %d.", block * BS, trigger_point);
//		packet.type = SR_DF_LOGIC;
//		packet.payload = &logic;
//		logic.length = trigger_point;
//		logic.unitsize = 1;
//		logic.data = devc->final_buf;
//		sr_session_send(devc->session_dev_id, &packet);
//	}

//	/* Send the SR_DF_TRIGGER packet to the session bus. */
//	sr_spew("Sending SR_DF_TRIGGER packet, sample = %d.",
//		(block * BS) + trigger_point);
//	packet.type = SR_DF_TRIGGER;
//	packet.payload = NULL;
//	sr_session_send(devc->session_dev_id, &packet);

//	/* If at least one sample is located after the trigger... */
//	if (trigger_point < (BS - 1)) {
//		/* Send post-trigger SR_DF_LOGIC packet to the session bus. */
//		sr_spew("Sending post-trigger SR_DF_LOGIC packet, "
//			"start = %d, length = %d.",
//			(block * BS) + trigger_point, BS - trigger_point);
//		packet.type = SR_DF_LOGIC;
//		packet.payload = &logic;
//		logic.length = BS - trigger_point;
//		logic.unitsize = 1;
//		logic.data = devc->final_buf + trigger_point;
//		sr_session_send(devc->session_dev_id, &packet);
//	}
}
