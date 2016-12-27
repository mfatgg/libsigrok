/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2012 mfatgg <mfatgg00@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ftdi.h>
#include <glib.h>
#include <string.h>
#include "libsigrok.h"
#include "libsigrok-internal.h"
#include "protocol.h"

SR_PRIV struct sr_dev_driver minila_mockup_driver_info;
static struct sr_dev_driver *di = &minila_mockup_driver_info;

/*
 */
static const uint16_t usb_pids[] = {
	0x6010,
};

/* Function prototypes. */
static int hw_dev_acquisition_stop(struct sr_dev_inst *sdi, void *cb_data);

static int clear_instances(void)
{
	GSList *l;
	struct sr_dev_inst *sdi;
	struct drv_context *drvc;
	struct dev_context *devc;

	drvc = di->priv;

	/* Properly close all devices. */
	for (l = drvc->instances; l; l = l->next) {
		if (!(sdi = l->data)) {
			/* Log error, but continue cleaning up the rest. */
			sr_err("%s: sdi was NULL, continuing.", __func__);
			continue;
		}
		if (sdi->priv) {
			devc = sdi->priv;
			ftdi_free(devc->ftdic);
		}
		sr_dev_inst_free(sdi);
	}
	g_slist_free(drvc->instances);
	drvc->instances = NULL;

	return SR_OK;
}

static int hw_init(void)
{
	struct drv_context *drvc;

	if (!(drvc = g_try_malloc0(sizeof(struct drv_context)))) {
		sr_err("Driver context malloc failed.");
		return SR_ERR_MALLOC;
	}

	di->priv = drvc;

	return SR_OK;
}

static GSList *hw_scan(GSList *options)
{
	struct sr_dev_inst *sdi;
	struct sr_probe *probe;
	struct drv_context *drvc;
	struct dev_context *devc;
	GSList *devices;
	unsigned int i;
	int ret;

	(void)options;

	drvc = di->priv;
	devices = NULL;

	/* Allocate memory for our private device context. */
	if (!(devc = g_try_malloc(sizeof(struct dev_context)))) {
		sr_err("Device context malloc failed.");
		goto err_free_nothing;
	}

	/* Set some sane defaults. */
	devc->ftdic = NULL;
	devc->cur_samplerate = SR_MHZ(100); /* 100MHz == max. samplerate */
	devc->limit_msec = 0;
	devc->limit_samples = 0;
	devc->session_dev_id = NULL;
	memset(devc->mangled_buf, 0, BS);
	devc->final_buf = NULL;
	devc->trigger_pattern = 0x00; /* Value irrelevant, see trigger_mask. */
	devc->trigger_mask = 0x00; /* All probes are "don't care". */
	devc->trigger_timeout = 10; /* Default to 10s trigger timeout. */
	devc->trigger_found = 0;
	devc->done = 0;
	devc->block_counter = 0;
	devc->divcount = 0; /* 10ns sample period == 100MHz samplerate */
	devc->usb_pid = 0;

	/* Allocate memory where we'll store the de-mangled data. */
	if (!(devc->final_buf = g_try_malloc(SDRAM_SIZE))) {
		sr_err("final_buf malloc failed.");
		goto err_free_devc;
	}

	/* Allocate memory for the FTDI context (ftdic) and initialize it. */
	if (!(devc->ftdic = ftdi_new())) {
		sr_err("%s: ftdi_new failed.", __func__);
		goto err_free_final_buf;
	}

	/* Check for the device and temporarily open it. */
	for (i = 0; i < ARRAY_SIZE(usb_pids); i++) {
		sr_dbg("Probing for VID/PID %04x:%04x.", USB_VENDOR_ID,
		       usb_pids[i]);
		ret = ftdi_usb_open_desc(devc->ftdic, USB_VENDOR_ID,
					 usb_pids[i], USB_DESCRIPTION, NULL);
		if (ret == 0) {
			sr_dbg("Found MINILA device (%04x:%04x).",
			       USB_VENDOR_ID, usb_pids[i]);
			devc->usb_pid = usb_pids[i];
		}
	}

	if (devc->usb_pid == 0)
		goto err_free_ftdic;

	/* Register the device with libsigrok. */
	sdi = sr_dev_inst_new(0, SR_ST_INITIALIZING,
			USB_VENDOR_NAME, USB_MODEL_NAME, USB_MODEL_VERSION);
	if (!sdi) {
		sr_err("%s: sr_dev_inst_new failed.", __func__);
		goto err_close_ftdic;
	}
	sdi->driver = di;
	sdi->priv = devc;

	for (i = 0; minila_probe_names[i]; i++) {
		if (!(probe = sr_probe_new(i, SR_PROBE_LOGIC, TRUE,
					minila_probe_names[i])))
			return NULL;
		sdi->probes = g_slist_append(sdi->probes, probe);
	}

	devices = g_slist_append(devices, sdi);
	drvc->instances = g_slist_append(drvc->instances, sdi);

	sr_spew("Device init successful.");

	/* Close device. We'll reopen it again when we need it. */
	(void) minila_close(devc); /* Log, but ignore errors. */

	return devices;

err_close_ftdic:
	(void) minila_close(devc); /* Log, but ignore errors. */
err_free_ftdic:
	free(devc->ftdic); /* NOT g_free()! */
err_free_final_buf:
	g_free(devc->final_buf);
err_free_devc:
	g_free(devc);
err_free_nothing:

	return NULL;
}

static GSList *hw_dev_list(void)
{
	struct drv_context *drvc;

	drvc = di->priv;

	return drvc->instances;
}

static int hw_dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	int ret;

	if (!(devc = sdi->priv)) {
		sr_err("%s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	sr_dbg("Opening MINILA device (%04x:%04x).", USB_VENDOR_ID,
	       devc->usb_pid);

	/* Open the device. */
	if ((ret = ftdi_usb_open_desc(devc->ftdic, USB_VENDOR_ID,
			devc->usb_pid, USB_DESCRIPTION, NULL)) < 0) {
		sr_err("%s: ftdi_usb_open_desc: (%d) %s",
		       __func__, ret, ftdi_get_error_string(devc->ftdic));
		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
		return SR_ERR;
	}
	sr_dbg("Device opened successfully.");

	/* Purge RX/TX buffers in the FTDI chip. */
	if ((ret = ftdi_usb_purge_buffers(devc->ftdic)) < 0) {
		sr_err("%s: ftdi_usb_purge_buffers: (%d) %s",
		       __func__, ret, ftdi_get_error_string(devc->ftdic));
		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
		goto err_dev_open_close_ftdic;
	}
	sr_dbg("FTDI buffers purged successfully.");

	/* Enable flow control in the FTDI chip. */
	if ((ret = ftdi_setflowctrl(devc->ftdic, SIO_RTS_CTS_HS)) < 0) {
		sr_err("%s: ftdi_setflowcontrol: (%d) %s",
		       __func__, ret, ftdi_get_error_string(devc->ftdic));
		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
		goto err_dev_open_close_ftdic;
	}
	sr_dbg("FTDI flow control enabled successfully.");

	//res := Set_USB_Device_LatencyTimer(16);
	//res := Set_USB_Device_BitMode($00,$00); 		// reset controller
	//res := Set_USB_Device_BitMode($00,$08); 		// enable Host Bus Emulation
	//res := Set_USB_Device_Timeouts(1000,1000); 		// enable Host Bus Emulation
//	if ((ret = ftdi_set_latency_timer(devc->ftdic, 16)) < 0) {
//		sr_err("%s: ftdi_set_latency_timer: (%d) %s",
//		       __func__, ret, ftdi_get_error_string(devc->ftdic));
//		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
//		goto err_dev_open_close_ftdic;
//	}
//	sr_dbg("FTDI latency set to 16 successfully.");
	if ((ret = ftdi_set_bitmode(devc->ftdic, 0, BITMODE_MCU)) < 0) {
		sr_err("%s: ftdi_set_bitmode: (%d) %s",
		       __func__, ret, ftdi_get_error_string(devc->ftdic));
		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
		goto err_dev_open_close_ftdic;
	}
	sr_dbg("FTDI bitmode set to MCU Host Bus Emulation mode successfully.");


	/* Wait 100ms. */
	g_usleep(100 * 1000);

	sdi->status = SR_ST_ACTIVE;

	return SR_OK;

err_dev_open_close_ftdic:
	(void) minila_close(devc); /* Log, but ignore errors. */
	return SR_ERR;
}

static int hw_dev_close(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;

	if (!(devc = sdi->priv)) {
		sr_err("%s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	sr_dbg("Closing device.");

	if (sdi->status == SR_ST_ACTIVE) {
		sr_dbg("Status ACTIVE, closing device.");
		(void) minila_close_usb_reset_sequencer(devc); /* Ignore errors. */
	} else {
		sr_spew("Status not ACTIVE, nothing to do.");
	}

	sdi->status = SR_ST_INACTIVE;

	sr_dbg("Freeing sample buffer.");
	g_free(devc->final_buf);

	return SR_OK;
}

static int hw_cleanup(void)
{
	if (!di->priv)
		/* Can get called on an unused driver, doesn't matter. */
		return SR_OK;

	clear_instances();

	return SR_OK;
}

static int hw_info_get(int info_id, const void **data,
		       const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;

	switch (info_id) {
	case SR_DI_HWCAPS:
		*data = minila_hwcaps;
		break;
	case SR_DI_NUM_PROBES:
		*data = GINT_TO_POINTER(NUM_PROBES);
		sr_spew("%s: Returning number of probes: %d.", __func__,
			NUM_PROBES);
		break;
	case SR_DI_PROBE_NAMES:
		*data = minila_probe_names;
		sr_spew("%s: Returning probenames.", __func__);
		break;
	case SR_DI_SAMPLERATES:
		minila_fill_supported_samplerates_if_needed();
		*data = &minila_samplerates;
		sr_spew("%s: Returning samplerates.", __func__);
		break;
	case SR_DI_TRIGGER_TYPES:
		*data = (char *)TRIGGER_TYPES;
		sr_spew("%s: Returning trigger types: %s.", __func__,
			TRIGGER_TYPES);
		break;
	case SR_DI_CUR_SAMPLERATE:
		if (sdi) {
			devc = sdi->priv;
			*data = &devc->cur_samplerate;
			sr_spew("%s: Returning samplerate: %" PRIu64 "Hz.",
				__func__, devc->cur_samplerate);
		} else
			return SR_ERR;
		break;
	default:
		return SR_ERR_ARG;
	}

	return SR_OK;
}

static int hw_dev_config_set(const struct sr_dev_inst *sdi, int hwcap,
		const void *value)
{
	struct dev_context *devc;

	if (!(devc = sdi->priv)) {
		sr_err("%s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	switch (hwcap) {
	case SR_HWCAP_SAMPLERATE:
		if (minila_set_samplerate(sdi, *(const uint64_t *)value) == SR_ERR) {
			sr_err("%s: setting samplerate failed.", __func__);
			return SR_ERR;
		}
		sr_dbg("SAMPLERATE = %" PRIu64, devc->cur_samplerate);
		break;
	case SR_HWCAP_LIMIT_MSEC:
		if (*(const uint64_t *)value == 0) {
			sr_err("%s: LIMIT_MSEC can't be 0.", __func__);
			return SR_ERR;
		}
		devc->limit_msec = *(const uint64_t *)value;
		sr_dbg("LIMIT_MSEC = %" PRIu64, devc->limit_msec);
		break;
	case SR_HWCAP_LIMIT_SAMPLES:
		if (*(const uint64_t *)value < MIN_NUM_SAMPLES) {
			sr_err("%s: LIMIT_SAMPLES too small.", __func__);
			return SR_ERR;
		}
		devc->limit_samples = *(const uint64_t *)value;
		sr_dbg("LIMIT_SAMPLES = %" PRIu64, devc->limit_samples);
		break;
	default:
		/* Unknown capability, return SR_ERR. */
		sr_err("%s: Unknown capability: %d.", __func__, hwcap);
		return SR_ERR;
		break;
	}

	return SR_OK;
}

static int receive_data(int fd, int revents, void *cb_data)
{
	int i, ret;
	struct sr_dev_inst *sdi;
	struct dev_context *devc;

	(void)fd;
	(void)revents;

	if (!(sdi = cb_data)) {
		sr_err("%s: cb_data was NULL.", __func__);
		return FALSE;
	}

	if (!(devc = sdi->priv)) {
		sr_err("%s: sdi->priv was NULL.", __func__);
		return FALSE;
	}

	if (!devc->ftdic) {
		sr_err("%s: devc->ftdic was NULL.", __func__);
		return FALSE;
	}

	/* Get one block of data. */
	if ((ret = minila_read_block(devc)) < 0) {
		sr_err("%s: minila_read_block error: %d.", __func__, ret);
		hw_dev_acquisition_stop(sdi, sdi);
		return FALSE;
	}

	/* We need to get exactly NUM_BLOCKS blocks (i.e. 8MB) of data. */
	if (devc->block_counter != (NUM_BLOCKS - 1)) {
		devc->block_counter++;
		return TRUE;
	}

	sr_dbg("Sampling finished, sending data to session bus now.");

	/* All data was received and demangled, send it to the session bus. */
	for (i = 0; i < NUM_BLOCKS; i++)
		minila_send_block_to_session_bus(devc, i);

	hw_dev_acquisition_stop(sdi, sdi);

	return TRUE;
}

static int hw_dev_acquisition_start(const struct sr_dev_inst *sdi,
				    void *cb_data)
{
	struct dev_context *devc;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_header header;
	struct sr_datafeed_meta_logic meta;
	uint8_t buf[128];
	int bytes_written, bytes_read;
	int i;
	time_t done, now;

	if (!(devc = sdi->priv)) {
		sr_err("%s: sdi->priv was NULL.", __func__);
		return SR_ERR_BUG;
	}

	if (!devc->ftdic) {
		sr_err("%s: devc->ftdic was NULL.", __func__);
		return SR_ERR_BUG;
	}

	devc->divcount = minila_samplerate_to_divcount(devc->cur_samplerate);
	if (devc->divcount == 0xff) {
		sr_err("%s: Invalid divcount/samplerate.", __func__);
		return SR_ERR;
	}

	if (minila_configure_probes(sdi) != SR_OK) {
		sr_err("Failed to configure probes.");
		return SR_ERR;
	}

	sr_dbg("Starting acquisition.");

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
	buf[12] = 0x00;  // 100 MHz samplerate
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


	sr_dbg("Acquisition started successfully.");

	devc->session_dev_id = cb_data;

	/* Send header packet to the session bus. */
	sr_dbg("Sending SR_DF_HEADER.");
	packet.type = SR_DF_HEADER;
	packet.payload = &header;
	header.feed_version = 1;
	gettimeofday(&header.starttime, NULL);
	sr_session_send(devc->session_dev_id, &packet);

	/* Send metadata about the SR_DF_LOGIC packets to come. */
	packet.type = SR_DF_META_LOGIC;
	packet.payload = &meta;
	meta.samplerate = devc->cur_samplerate;
	meta.num_probes = NUM_PROBES;
	sr_session_send(devc->session_dev_id, &packet);

	/* Time when we should be done (for detecting trigger timeouts). */
	devc->done = (devc->divcount + 1) * 0.08388608 + time(NULL)
			+ devc->trigger_timeout;
	devc->block_counter = 0;
	devc->trigger_found = 0;

	/* Hook up a dummy handler to receive data from the MINILA. */
	sr_source_add(-1, G_IO_IN, 0, receive_data, (void *)sdi);

	return SR_OK;
}

static int hw_dev_acquisition_stop(struct sr_dev_inst *sdi, void *cb_data)
{
	struct sr_datafeed_packet packet;

	(void)sdi;

	sr_dbg("Stopping acquisition.");
	sr_source_remove(-1);

	/* Send end packet to the session bus. */
	sr_dbg("Sending SR_DF_END.");
	packet.type = SR_DF_END;
	sr_session_send(cb_data, &packet);

	return SR_OK;
}

SR_PRIV struct sr_dev_driver minila_mockup_driver_info = {
	.name = "minila-mockup",
	.longname = "miniLA USB Interface",
	.api_version = 1,
	.init = hw_init,
	.cleanup = hw_cleanup,
	.scan = hw_scan,
	.dev_list = hw_dev_list,
	.dev_clear = clear_instances,
	.dev_open = hw_dev_open,
	.dev_close = hw_dev_close,
	.info_get = hw_info_get,
	.dev_config_set = hw_dev_config_set,
	.dev_acquisition_start = hw_dev_acquisition_start,
	.dev_acquisition_stop = hw_dev_acquisition_stop,
	.priv = NULL,
};
