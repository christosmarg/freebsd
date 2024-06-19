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

#ifndef _AUDIO_H_
#define _AUDIO_H_

#include <sys/cdefs.h>
#include <sys/soundcard.h>

#include <limits.h>
#include <mixer.h>
#include <stdbool.h>

#define AUDIO_DEFAULT_FORMAT	AFMT_S16_NE
#define AUDIO_DEFAULT_CHANNELS	1
#define AUDIO_DEFAULT_RATE	44100

#define AUDIO_VOLMIN		0
#define AUDIO_VOLMAX		100

struct audio_channel {
	char name[NAME_MAX];
	int unit;
	int caps;
	int rate;
	int format;
	int min_rate;
	int max_rate;
	size_t bufsz;
	size_t sample_size;
	size_t frame_size;
	int frame_total;
	char *map;
	struct audio_device *device;
};

struct audio_device {
#define AUDIO_REC	0x0001
#define AUDIO_PLAY	0x0002
#define AUDIO_NBIO	0x0004
#define AUDIO_EXCL	0x0008
#define AUDIO_MMAP	0x0010
	int open_mode;
	int fd;
	int unit;
	char name[NAME_MAX];
	char desc[NAME_MAX];
	char devnode[NAME_MAX];
	bool is_default;
	int caps;
	int format;		/* XXX do we need it here as well? */
	int rate;		/* XXX do we need it here as well? */
	int channels;
	struct mixer *mixer;
	struct audio_channel *chan_in;
	struct audio_channel *chan_out;
};

struct midi_device {
#define MIDI_IN		0x0001
#define MIDI_OUT	0x0002
#define MIDI_NBIO	0x0004
	int open_mode;
	int fd;
	/* TODO add more once we have better support */
};

__BEGIN_DECLS

struct audio_device *audio_open(const char *, int, int, int, int);
int audio_close(struct audio_device *);
ssize_t audio_read(struct audio_device *, void *, size_t);
ssize_t audio_write(struct audio_device *, void *, size_t);
int audio_set_vol(struct audio_channel *, int);
int audio_get_vol(struct audio_channel *c);

struct midi_device *midi_open(const char *, int);
int midi_close(struct midi_device *);
ssize_t midi_read(struct midi_device *, void *, size_t);
ssize_t midi_write(struct midi_device *, void *, size_t);

__END_DECLS

#endif /* _AUDIO_H_ */
