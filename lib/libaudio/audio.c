/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Christos Margiolis <christos@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/mman.h>
#include <sys/nv.h>
#include <sys/sndstat.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "audio.h"

#define DSP_BASEPATH	"/dev/dsp"

#define LOG_HELPER(fmt, ...)	\
	syslog(LOG_ERR, "%s:%d: " fmt "%s\n", __func__, __LINE__, __VA_ARGS__)
#define LOG(...)		\
	LOG_HELPER(__VA_ARGS__, "")

/* TODO expose it in header file? */
static int
audio_fmt2bytes(int fmt)
{
	if (fmt & (AFMT_S8 | AFMT_U8))
		return (1);
	else if (fmt & (AFMT_S16_NE | AFMT_U16_NE))
		return (2);
	else if (fmt & (AFMT_S24_NE | AFMT_U24_NE))
		return (3);
	else if (fmt & (AFMT_S32_NE | AFMT_U32_NE))
		return (4);
	else {
		LOG("unknown format: %#08x", fmt);
		return (0);
	}
}

struct audio_device *
audio_open(const char *path, int open_mode, int format, int channels, int rate)
{
	struct audio_device *d;
	struct audio_channel *c;
	struct sndstioc_nv_arg arg = {0};
	const nvlist_t * const *di;
	const nvlist_t * const *cdi;
	nvlist_t *nvl = NULL;
	oss_audioinfo ai;
	oss_sysinfo si;
	audio_buf_info bi;
	char buf[NAME_MAX];
	size_t i, n;
	int stfd = -1, tmp;

	if ((d = calloc(1, sizeof(struct audio_device))) == NULL) {
		LOG("cannot allocate audio_device");
		goto fail;
	}

	open_mode &= AUDIO_REC | AUDIO_PLAY | AUDIO_NBIO |
	    AUDIO_EXCL | AUDIO_MMAP;
	if (!open_mode) {
		LOG("no valid open mode specified");
		errno = EINVAL;
		goto fail;
	}

	tmp = 0;
	if ((open_mode & (AUDIO_REC | AUDIO_PLAY)) == (AUDIO_REC | AUDIO_PLAY))
		tmp |= O_RDWR;
	else if (open_mode & AUDIO_REC)
		tmp |= O_RDONLY;
	else if (open_mode & AUDIO_PLAY)
		tmp |= O_WRONLY;
	else {
		LOG("please specify at least one audio direction");
		errno = EINVAL;
		goto fail;
	}
	if (open_mode & AUDIO_NBIO)
		tmp |= O_NONBLOCK;
	if (open_mode & AUDIO_EXCL)
		tmp |= O_EXCL;

	if (path == NULL || strcmp(path, DSP_BASEPATH) == 0) {
		d->unit = -1;
		path = DSP_BASEPATH;
	} else {
		/* TODO handle relative and userdev paths */
		d->unit = strtol(path + strlen(DSP_BASEPATH), NULL, 10);
		if (errno == EINVAL || errno == ERANGE) {
			LOG("strtol(%s) failed", path + strlen(DSP_BASEPATH));
			goto fail;
		}
	}

	if ((d->fd = open(path, tmp)) < 0) {
		LOG("open(%s, %#04x) failed", path, tmp);
		goto fail;
	}

	ai.dev = d->unit;
	if (ioctl(d->fd,
	    open_mode & AUDIO_EXCL ? SNDCTL_AUDIOINFO_EX : SNDCTL_AUDIOINFO,
	    &ai) < 0) {
		LOG("ioctl(SNDCTL_AUDIOINFO%s, %d) failed",
		    d->open_mode & AUDIO_EXCL ? "_EX" : "", d->unit);
		goto fail;
	}
	d->unit = ai.dev;
	d->caps = ai.caps;
	d->is_default = d->unit == mixer_get_dunit();
	d->open_mode = open_mode;
	strlcpy(d->desc, ai.name, sizeof(d->desc));
	strlcpy(d->devnode, ai.devnode, sizeof(d->devnode));

	mixer_get_path(buf, sizeof(buf), d->unit);
	d->mixer = mixer_open(buf);

	if (ioctl(d->fd, OSS_SYSINFO, &si) < 0) {
		LOG("ioctl(OSS_SYSINFO) failed");
		goto fail;
	}

	/* Memory map prior to FreeBSD 13.2 may use wrong buffer sizes. */
	if (strncmp(si.version, "1302000", 7) < 0) {
		if (d->open_mode & AUDIO_MMAP) {
			LOG("memory map not working properly prior to 13.2");
			errno = ENODEV;
			goto fail;
		}
		d->caps &= ~PCM_CAP_MMAP;
	}

	/*
	 * Read /dev/sndstat nvlist for some contents we cannot fetch from the
	 * AUDIOINFO/ENGINEINFO IOCTLs.
	 *
	 * Do this first so that we can assign d->name as early as possible for
	 * more helpful error messages and also to exit early in case we hit an
	 * error here.
	 */
	if ((stfd = open("/dev/sndstat", O_RDONLY)) < 0) {
		LOG("open(/dev/sndstat) failed");
		goto fail;
	}
	if (ioctl(stfd, SNDSTIOC_REFRESH_DEVS, NULL) < 0) {
		LOG("ioctl(SNDSTIOC_REFRESH_DEVS) failed");
		goto fail;
	}
	arg.nbytes = 0;
	arg.buf = NULL;
	if (ioctl(stfd, SNDSTIOC_GET_DEVS, &arg) < 0) {
		LOG("ioctl(SNDSTIOC_GET_DEVS#1) failed");
		goto fail;
	}
	if ((arg.buf = malloc(arg.nbytes)) == NULL) {
		LOG("cannot allocate sndstat buffer");
		goto fail;
	}
	if (ioctl(stfd, SNDSTIOC_GET_DEVS, &arg) < 0) {
		LOG("ioctl(SNDSTIOC_GET_DEVS#2) failed");
		goto fail;
	}
	nvl = nvlist_unpack(arg.buf, arg.nbytes, 0);
	di = nvlist_get_nvlist_array(nvl, SNDST_DSPS, &n);

	/* Search for our device. */
	for (i = 0; i < n; i++)
		if (i == (size_t)d->unit)
			break;
	if (i == n) {
		LOG("cannot find device %d in sndstat nvlist", d->unit);
		errno = ENODEV;
		goto fail;
	}

	strlcpy(d->name, nvlist_get_string(di[i], SNDST_DSPS_NAMEUNIT),
	    sizeof(d->name));

	if (!nvlist_exists(di[i], SNDST_DSPS_PROVIDER_INFO)) {
		LOG("%s: provider info nvlist not found", d->name);
		errno = ENODEV;
		goto fail;
	}

	if ((d->open_mode & (AUDIO_NBIO | AUDIO_MMAP)) &&
	    (d->caps & PCM_CAP_TRIGGER) == 0) {
		LOG("%s: triggering not supported", d->name);
		errno = ENODEV;
		goto fail;
	}

	if ((d->open_mode & AUDIO_MMAP) && (d->caps & PCM_CAP_MMAP) == 0) {
		LOG("%s: memory mapping not supported", d->name);
		errno = ENODEV;
		goto fail;
	}

	/*
	 * Disable format conversions if we are in exclusive or memory map
	 * mode.
	 */
	if (d->open_mode & (AUDIO_EXCL | AUDIO_MMAP)) {
		/*
		 * The OSS docs advise against checking the return value of
		 * this IOCTL.
		 */
		n = 0;
		ioctl(d->fd, SNDCTL_DSP_COOKEDMODE, &n);
	}

	/* Set sample format. */
	if (format <= 0)
		format = AUDIO_DEFAULT_FORMAT;
	tmp = format;
	if (ioctl(d->fd, SNDCTL_DSP_SETFMT, &tmp) < 0) {
		LOG("%s: ioctl(SNDCTL_DSP_SETFMT, %#08x) failed",
		    d->name, format);
		goto fail;
	}
	if (tmp != format) {
		LOG("%s: driver forced sample format: %#08x -> %#08x",
		    d->name, format, tmp);
	}
	d->format = tmp;

	/* Set sample channels. */
	if (channels <= 0)
		channels = AUDIO_DEFAULT_CHANNELS;
	tmp = channels;
	if (ioctl(d->fd, SNDCTL_DSP_CHANNELS, &tmp) < 0) {
		LOG("%s: ioctl(SNDCTL_DSP_CHANNELS, %d) failed",
		    d->name, channels);
		goto fail;
	}
	if (tmp != channels) {
		LOG("%s: driver forced sample channels: %d -> %d",
		    d->name, channels, tmp);
	}
	d->channels = tmp;

	/* Set sample rate. */
	if (rate <= 0)
		rate = AUDIO_DEFAULT_RATE;
	tmp = rate;
	if (ioctl(d->fd, SNDCTL_DSP_SPEED, &tmp) < 0) {
		LOG("%s: ioctl(SNDCTL_DSP_SPEED, %d) failed", d->name, rate);
		goto fail;
	}
	if (tmp != rate) {
		LOG("%s: driver forced sample rate: %d -> %d",
		    d->name, rate, tmp);
	}
	d->rate = tmp;
	cdi = nvlist_get_nvlist_array(
	    nvlist_get_nvlist(di[i], SNDST_DSPS_PROVIDER_INFO),
	    SNDST_DSPS_SOUND4_CHAN_INFO, &n);

	for (i = 0; i < n; i++) {
		ai.dev = i;
		if (ioctl(d->fd, SNDCTL_ENGINEINFO, &ai) < 0) {
			LOG("%s: ioctl(SNDCTL_ENGINEINFO, %zu) failed",
			    d->name, i);
			goto fail;
		}
		/* We only care about our process' channel(s). */
		if (getpid() != ai.pid)
			continue;
		if ((c = calloc(1, sizeof(struct audio_channel))) == NULL) {
			LOG("%s: cannot allocate audio_channel", d->name);
			goto fail;
		}
		c->device = d;
		strlcpy(c->name, ai.name, sizeof(c->name));
		c->unit = ai.dev;
		c->caps = ai.caps;
		c->min_rate = ai.min_rate;
		c->max_rate = ai.max_rate;
#define NV(type, id)	\
	nvlist_get_ ## type (cdi[i], SNDST_DSPS_SOUND4_CHAN_ ## id)
		c->format = NV(number, FORMAT);
		c->rate = NV(number, RATE);
#undef NV
		/* TODO handle buffer size assignment */
		if (c->caps & PCM_CAP_INPUT) {
			if (ioctl(d->fd, SNDCTL_DSP_GETISPACE, &bi) < 0) {
				LOG("%s: ioctl(SNDCTL_DSP_GETISPACE)", c->name);
				goto fail;
			}
			tmp = PROT_READ;
			d->chan_in = c;
		} else if (c->caps & PCM_CAP_OUTPUT) {
			if (ioctl(d->fd, SNDCTL_DSP_GETOSPACE, &bi) < 0) {
				LOG("%s: ioctl(SNDCTL_DSP_GETOSPACE)", c->name);
				goto fail;
			}
			tmp = PROT_WRITE;
			d->chan_out = c;
		}

		c->bufsz = bi.fragstotal * bi.fragsize;
		c->sample_size = audio_fmt2bytes(c->format);
		c->frame_size = c->sample_size * d->channels;
		c->frame_total = c->bufsz / c->frame_size;

		/* Memory map buffer */
		if (d->open_mode & AUDIO_MMAP) {
			c->map = mmap(NULL, c->bufsz, tmp,
			    MAP_FILE | MAP_SHARED, d->fd, 0);
			if (c->map == MAP_FAILED) {
				LOG("%s: cannot mmap %s buffer",
				    c->name, tmp == PROT_READ ?
				    "recording" : "playback");
				goto fail;
			}
			for (i = 0; i < c->bufsz; i++)
				c->map[i] = 0;
		}
	}
	if (d->chan_in == NULL && d->chan_out == NULL) {
		LOG("%s: no channels allocated", d->name);
		errno = ENODEV;
		goto fail;
	}

	/* Trigger channel start */
	if (d->open_mode & (AUDIO_NBIO | AUDIO_MMAP)) {
		tmp = 0;
		if (ioctl(d->fd, SNDCTL_DSP_SETTRIGGER, &tmp) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_SETTRIGGER#1) failed",
			    d->name);
			goto fail;
		}

		tmp = 0;
		if (d->chan_in != NULL)
			tmp |= PCM_ENABLE_INPUT;
		if (d->chan_out != NULL)
			tmp |= PCM_ENABLE_OUTPUT;
		if (ioctl(d->fd, SNDCTL_DSP_SETTRIGGER, &tmp) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_SETTRIGGER#2) failed",
			    d->name);
			goto fail;
		}
	}

	close(stfd);
	free(arg.buf);
	nvlist_destroy(nvl);

	return (d);

fail:
	close(stfd);
	nvlist_destroy(nvl);
	if (arg.buf != NULL)
		free(arg.buf);
	if (d != NULL)
		audio_close(d);

	return (NULL);
}

int
audio_close(struct audio_device *d)
{
	struct audio_channel *c;
	int rc;

	if (d == NULL)
		return (0);

	rc = close(d->fd);
	if (d->chan_in != NULL) {
		c = d->chan_in;
		if (d->open_mode & AUDIO_MMAP)
			munmap(c->map, c->bufsz);
		free(c);
	}
	if (d->chan_out != NULL) {
		c = d->chan_out;
		if (d->open_mode & AUDIO_MMAP)
			munmap(c->map, c->bufsz);
		free(c);
	}
	free(d);

	return (rc);
}

static ssize_t
audio_io(struct audio_device *d, void *buf, size_t nbytes, bool rd)
{
	struct audio_channel *c;
	struct pollfd pfd;
	count_info ci;
	char *data;
	size_t todo;
	ssize_t n;
	int event;

	if (d == NULL) {
		LOG("device is null");
		errno = EINVAL;
		return (-1);
	}

	if ((rd && d->chan_in == NULL) || (!rd && d->chan_out == NULL)) {
		LOG("%s: no %s channel", d->name, rd ? "recording" : "playback");
		errno = EINVAL;
		return (-1);
	}

	c = rd ? d->chan_in : d->chan_out;

	if (nbytes == 0)
		return (0);
	if (nbytes > c->bufsz && rd)	/* XXX */
		nbytes = c->bufsz;

	for (data = buf, todo = nbytes; todo > 0;) {
		/* Wait for events. */
		if (d->open_mode & (AUDIO_NBIO | AUDIO_MMAP)) {
			event = rd ? POLLIN : POLLOUT;

			pfd.fd = d->fd;
			pfd.events = event;
			while (poll(&pfd, 1, -1) < 0) {
				if (errno == EINTR)
					continue;
				LOG("%s: %s poll() failed",
				    c->name, rd ? "recording" : "playback");
				return (-1);
			}
			if (pfd.revents & POLLHUP) {
				errno = ENODEV;
				return (-1);
			}
			if ((pfd.revents & event) == 0)
				continue;
		}

		/* FIXME */
		/* Calculate payload in case of mmap. */
		if (d->open_mode & AUDIO_MMAP) {
			if (ioctl(d->fd, rd ? SNDCTL_DSP_GETIPTR :
			    SNDCTL_DSP_GETOPTR, &ci) < 0) {
				LOG("%s: ioctl(SNDCTL_DSP_GET%sPTR) failed",
				    c->name, rd ? "I" : "O");
				return (-1);
			}
			if (!ci.bytes)
				continue;
			ci.ptr %= c->bufsz - 1;
			n = c->bufsz - ci.ptr;
			if ((size_t)n > todo)
				n = todo;
			LOG("todo=%ld, ptr=%d, n=%ld", todo, ci.ptr, n);
		}

		/* Do the actual reading/writing. */
		if (rd) {
			if (d->open_mode & AUDIO_MMAP) {
				memcpy(data, c->map + ci.ptr, n);
			} else {
				n = read(d->fd, data, todo);
				if (errno == EAGAIN)
					continue;
			}
		} else {
			if (d->open_mode & AUDIO_MMAP) {
				memcpy(c->map + ci.ptr, data, n);
			} else {
				n = write(d->fd, data, todo);
				if (errno == EAGAIN)
					continue;
			}
		}
		if (n >= 0) {
			data += n;
			todo -= n;
		} else {
			LOG("%s: failed to %s: %s", rd ? "read" : "write",
			    c->name, strerror(errno));
			return (-1);
		}
	}

	return (nbytes - todo);
}

ssize_t
audio_read(struct audio_device *d, void *buf, size_t nbytes)
{
	return (audio_io(d, buf, nbytes, true));
}

ssize_t
audio_write(struct audio_device *d, void *buf, size_t nbytes)
{
	return (audio_io(d, buf, nbytes, false));
}

int
audio_set_vol(struct audio_channel *c, int vol)
{
	if (c == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * We could disallow volumes outside the AUDIO_VOLMIN-AUDIO_VOLMAX
	 * range, but sound(4) will cap them anyway.
	 */
	if (c->caps & PCM_CAP_INPUT) {
		if (ioctl(c->device->fd, SNDCTL_DSP_SETRECVOL, &vol) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_SETRECVOL) failed", c->name);
			return (-1);
		}
	} else if (c->caps & PCM_CAP_OUTPUT) {
		if (ioctl(c->device->fd, SNDCTL_DSP_SETPLAYVOL, &vol) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_SETPLAYVOL) failed", c->name);
			return (-1);
		}
	}

	return (0);
}

int
audio_get_vol(struct audio_channel *c)
{
	int vol = 0;

	if (c == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (c->caps & PCM_CAP_INPUT) {
		if (ioctl(c->device->fd, SNDCTL_DSP_GETRECVOL, &vol) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_SETRECVOL) failed", c->name);
			return (-1);
		}
	} else if (c->caps & PCM_CAP_OUTPUT) {
		if (ioctl(c->device->fd, SNDCTL_DSP_GETPLAYVOL, &vol) < 0) {
			LOG("%s: ioctl(SNDCTL_DSP_GETPLAYVOL) failed", c->name);
			return (-1);
		}
	}

	return (vol);
}

struct midi_device *
midi_open(const char *path, int open_mode)
{
	struct midi_device *d = NULL;
	int tmp;

	if (path == NULL) {
		LOG("path not specified");
		errno = EINVAL;
		goto fail;
	}

	if ((d = calloc(1, sizeof(struct midi_device))) == NULL) {
		LOG("cannot allocate midi_device");
		goto fail;
	}

	open_mode &= MIDI_IN | MIDI_OUT | MIDI_NBIO;
	if (!open_mode) {
		LOG("no valid open mode specified");
		errno = EINVAL;
		goto fail;
	}

	tmp = 0;
	if ((open_mode & (MIDI_IN | MIDI_OUT)) == (MIDI_IN | MIDI_OUT))
		tmp |= O_RDWR;
	else if (open_mode & MIDI_IN)
		tmp |= O_RDONLY;
	else if (open_mode & MIDI_OUT)
		tmp |= O_WRONLY;
	else {
		LOG("please specify at least one midi direction");
		errno = EINVAL;
		goto fail;
	}
	if (open_mode & MIDI_NBIO)
		tmp |= O_NONBLOCK;

	/* XXX patch checks like in audio_open()? */

	if ((d->fd = open(path, tmp)) < 0) {
		LOG("open(%s, %#04x) failed", path, tmp);
		goto fail;
	}

	d->open_mode = open_mode;

	return (d);

fail:
	if (d != NULL)
		midi_close(d);

	return (NULL);
}

int
midi_close(struct midi_device *d)
{
	int rc;

	rc = close(d->fd);
	free(d);

	return (rc);
}

static ssize_t
midi_io(struct midi_device *d, void *buf, size_t nbytes, bool rd)
{
	struct pollfd pfd;
	char *data;
	size_t todo;
	ssize_t n;
	int event;

	if (d == NULL) {
		LOG("device is null");
		errno = EINVAL;
		return (-1);
	}

	if (nbytes == 0)
		return (0);

	for (data = buf, todo = nbytes; todo > 0;) {
		/* Wait for events. */
		if (d->open_mode & MIDI_NBIO) {
			event = rd ? POLLIN : POLLOUT;

			pfd.fd = d->fd;
			pfd.events = event;
			while (poll(&pfd, 1, -1) < 0) {
				if (errno == EINTR)
					continue;
				LOG("%s poll() failed",
				    rd ? "input" : "output");
				return (-1);
			}
			if (pfd.revents & POLLHUP) {
				errno = ENODEV;
				return (-1);
			}
			if ((pfd.revents & event) == 0)
				continue;
		}

		/* Do the actual reading/writing. */
		if (rd)
			n = read(d->fd, data, todo);
		else
			n = write(d->fd, data, todo);
		if (errno == EAGAIN)
			continue;
		if (n >= 0) {
			data += n;
			todo -= n;
		} else {
			LOG("failed to %s: %s", rd ? "read" : "write",
			    strerror(errno));
			return (-1);
		}
	}

	return (nbytes - todo);
}

ssize_t
midi_read(struct midi_device *d, void *buf, size_t nbytes)
{
	return (midi_io(d, buf, nbytes, true));
}

ssize_t
midi_write(struct midi_device *d, void *buf, size_t nbytes)
{
	return (midi_io(d, buf, nbytes, false));
}
