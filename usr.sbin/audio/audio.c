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

#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/sndstat.h>
#include <sys/soundcard.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <mixer.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct audio_chan {
	char name[NAME_MAX];
	char parentchan[NAME_MAX];
	int unit;
	char caps[BUFSIZ];
	int latency;
	int rate;
	char format[NAME_MAX];
	int pid;
	char proc[NAME_MAX];
	int interrupts;
	int xruns;
	int feedcount;
	int volume;
	struct {
		char format[BUFSIZ];
		int size_bytes;
		int size_frames;
		int blksz;
		int blkcnt;
		int free;
		int ready;
	} hwbuf, swbuf;
	char feederchain[BUFSIZ];
	struct audio_dev *dev;
	TAILQ_ENTRY(audio_chan) next;
};

struct audio_dev {
	char name[NAME_MAX];
	char desc[NAME_MAX];
	char devnode[NAME_MAX];
	char status[BUFSIZ];
	int unit;
	char caps[BUFSIZ];
	int from_user;
	int bitperfect;
	struct {
		int hwchans;
		int min_rate;
		int max_rate;
		int min_chn;
		int max_chn;
		char formats[BUFSIZ];
		int vchans;
		int vchanrate;
		char vchanformat[NAME_MAX];
	} play, rec;
	TAILQ_HEAD(, audio_chan) chans;
};

struct audio_ctl {
	const char *name;
	size_t off;
#define STR	0
#define NUM	1
#define VOL	2
#define GRP	3
	int type;
	int (*mod)(struct audio_dev *, void *);
};

struct map {
	int val;
	const char *str;
};

static int mod_bitperfect(struct audio_dev *, void *);
static int mod_play_vchans(struct audio_dev *, void *);
static int mod_play_vchanrate(struct audio_dev *, void *);
static int mod_play_vchanformat(struct audio_dev *, void *);
static int mod_rec_vchans(struct audio_dev *, void *);
static int mod_rec_vchanrate(struct audio_dev *, void *);
static int mod_rec_vchanformat(struct audio_dev *, void *);

static struct audio_ctl dev_ctls[] = {
#define F(member)	offsetof(struct audio_dev, member)
	{ "name",		F(name),		STR,	NULL },
	{ "desc",		F(desc),		STR,	NULL },
	{ "devnode",		F(devnode),		STR,	NULL },
	{ "status",		F(status),		STR,	NULL },
	{ "unit",		F(unit),		NUM,	NULL },
	{ "caps",		F(caps),		STR,	NULL },
	{ "from_user",		F(from_user),		NUM,	NULL },
	{ "bitperfect",		F(bitperfect),		NUM,	mod_bitperfect },
	{ "play",		F(play),		GRP,	NULL },
	{ "play.hwchans",	F(play.hwchans),	NUM,	NULL },
	{ "play.min_rate",	F(play.min_rate),	NUM,	NULL },
	{ "play.max_rate",	F(play.max_rate),	NUM,	NULL },
	{ "play.min_chn",	F(play.min_chn),	NUM,	NULL },
	{ "play.max_chn",	F(play.max_chn),	NUM,	NULL },
	{ "play.formats",	F(play.formats),	STR,	NULL },
	{ "play.vchans",	F(play.vchans),		NUM,	mod_play_vchans },
	{ "play.vchanrate",	F(play.vchanrate),	NUM,	mod_play_vchanrate },
	{ "play.vchanformat",	F(play.vchanformat),	STR,	mod_play_vchanformat },
	{ "rec",		F(rec),			GRP,	NULL },
	{ "rec.hwchans",	F(rec.hwchans),		NUM,	NULL },
	{ "rec.min_rate",	F(rec.min_rate),	NUM,	NULL },
	{ "rec.max_rate",	F(rec.max_rate),	NUM,	NULL },
	{ "rec.min_chn",	F(rec.min_chn),		NUM,	NULL },
	{ "rec.max_chn",	F(rec.max_chn),		NUM,	NULL },
	{ "rec.formats",	F(rec.formats),		STR,	NULL },
	{ "rec.vchans",		F(rec.vchans),		NUM,	mod_rec_vchans },
	{ "rec.vchanrate",	F(rec.vchanrate),	NUM,	mod_rec_vchanrate },
	{ "rec.vchanformat",	F(rec.vchanformat),	STR,	mod_rec_vchanformat },
	{ NULL,			0,			0,	NULL }
#undef F
};

static struct audio_ctl chan_ctls[] = {
#define F(member)	offsetof(struct audio_chan, member)
	{ "name",		F(name),		STR,	NULL },
	{ "parentchan",		F(parentchan),		STR,	NULL },
	{ "unit",		F(unit),		NUM,	NULL },
	{ "caps",		F(caps),		STR,	NULL },
	{ "latency",		F(latency),		NUM,	NULL },
	{ "rate",		F(rate),		NUM,	NULL },
	{ "format",		F(format),		STR,	NULL },
	{ "pid",		F(pid),			NUM,	NULL },
	{ "proc",		F(proc),		STR,	NULL },
	{ "interrupts",		F(interrupts),		NUM,	NULL },
	{ "xruns",		F(xruns),		NUM,	NULL },
	{ "feedcount",		F(feedcount),		NUM,	NULL },
	{ "volume",		F(volume),		VOL,	NULL },
	{ "hwbuf",		F(hwbuf),		GRP,	NULL },
	{ "hwbuf.format",	F(hwbuf.format),	STR,	NULL },
	{ "hwbuf.size_bytes",	F(hwbuf.size_bytes),	NUM,	NULL },
	{ "hwbuf.size_frames",	F(hwbuf.size_frames),	NUM,	NULL },
	{ "hwbuf.blksz",	F(hwbuf.blksz),		NUM,	NULL },
	{ "hwbuf.blkcnt",	F(hwbuf.blkcnt),	NUM,	NULL },
	{ "hwbuf.free",		F(hwbuf.free),		NUM,	NULL },
	{ "hwbuf.ready",	F(hwbuf.ready),		NUM,	NULL },
	{ "swbuf",		F(swbuf),		GRP,	NULL },
	{ "swbuf.format",	F(swbuf.format),	STR,	NULL },
	{ "swbuf.size_bytes",	F(swbuf.size_bytes),	NUM,	NULL },
	{ "swbuf.size_frames",	F(swbuf.size_frames),	NUM,	NULL },
	{ "swbuf.blksz",	F(swbuf.blksz),		NUM,	NULL },
	{ "swbuf.blkcnt",	F(swbuf.blkcnt),	NUM,	NULL },
	{ "swbuf.free",		F(swbuf.free),		NUM,	NULL },
	{ "swbuf.ready",	F(swbuf.ready),		NUM,	NULL },
	{ "feederchain",	F(feederchain),		STR,	NULL },
	{ NULL,			0,			0,	NULL }
#undef F
};

/*
 * Taken from the OSSv4 manual. Not all of them are supported on FreeBSD
 * however, and some of them are obsolete.
 */
static struct map capmap[] = {
	{ PCM_CAP_ANALOGIN,	"PCM_CAP_ANALOGIN" },
	{ PCM_CAP_ANALOGOUT,	"PCM_CAP_ANALOGOUT" },
	{ PCM_CAP_BATCH,	"PCM_CAP_BATCH" },
	{ PCM_CAP_BIND,		"PCM_CAP_BIND" },
	{ PCM_CAP_COPROC,	"PCM_CAP_COPROC" },
	{ PCM_CAP_DEFAULT,	"PCM_CAP_DEFAULT" },
	{ PCM_CAP_DIGITALIN,	"PCM_CAP_DIGITALIN" },
	{ PCM_CAP_DIGITALOUT,	"PCM_CAP_DIGITALOUT" },
	{ PCM_CAP_DUPLEX,	"PCM_CAP_DUPLEX" },
	{ PCM_CAP_FREERATE,	"PCM_CAP_FREERATE" },
	{ PCM_CAP_HIDDEN,	"PCM_CAP_HIDDEN" },
	{ PCM_CAP_INPUT,	"PCM_CAP_INPUT" },
	{ PCM_CAP_MMAP,		"PCM_CAP_MMAP" },
	{ PCM_CAP_MODEM,	"PCM_CAP_MODEM" },
	{ PCM_CAP_MULTI,	"PCM_CAP_MULTI" },
	{ PCM_CAP_OUTPUT,	"PCM_CAP_OUTPUT" },
	{ PCM_CAP_REALTIME,	"PCM_CAP_REALTIME" },
	{ PCM_CAP_REVISION,	"PCM_CAP_REVISION" },
	{ PCM_CAP_SHADOW,	"PCM_CAP_SHADOW" },
	{ PCM_CAP_SPECIAL,	"PCM_CAP_SPECIAL" },
	{ PCM_CAP_TRIGGER,	"PCM_CAP_TRIGGER" },
	{ PCM_CAP_VIRTUAL,	"PCM_CAP_VIRTUAL" },
	{ 0,			NULL }
};

static struct map fmtmap[] = {
	{ AFMT_A_LAW,		"alaw" },
	{ AFMT_MU_LAW,		"mulaw" },
	{ AFMT_S8,		"s8" },
	{ AFMT_U8,		"u8" },
	{ AFMT_S16_LE,		"s16le" },
	{ AFMT_S16_BE,		"s16be" },
	{ AFMT_U16_LE,		"u16le" },
	{ AFMT_U16_BE,		"u16be" },
	{ AFMT_S24_LE,		"s24le" },
	{ AFMT_S24_BE,		"s24be" },
	{ AFMT_U24_LE,		"u24le" },
	{ AFMT_U24_BE,		"u24be" },
	{ AFMT_S32_LE,		"s32le" },
	{ AFMT_S32_BE,		"s32be" },
	{ AFMT_U32_LE,		"u32le" },
	{ AFMT_U32_BE,		"u32be" },
	{ AFMT_AC3,		"ac3" },
	{ 0,			NULL }
};

static bool oflag = false;
static bool vflag = false;

static void
cap2str(char *buf, size_t size, int caps)
{
	struct map *p;

	for (p = capmap; p->str != NULL; p++) {
		if ((p->val & caps) == 0)
			continue;
		strlcat(buf, p->str, size);
		strlcat(buf, ",", size);
	}
	if (*buf == '\0')
		strlcpy(buf, "UNKNOWN", size);
	else
		buf[strlen(buf) - 1] = '\0';
}

static void
fmt2str(char *buf, size_t size, int fmt)
{
	struct map *p;
	int enc, ch, ext;

	enc = fmt & 0xf00fffff;
	ch = (fmt & 0x07f00000) >> 20;
	ext = (fmt & 0x08000000) >> 27;

	for (p = fmtmap; p->str != NULL; p++) {
		if ((p->val & enc) == 0)
			continue;
		strlcat(buf, p->str, size);
		if (ch) {
			snprintf(buf + strlen(buf), size,
			    ":%d.%d", ch - ext, ext);
		}
		strlcat(buf, ",", size);
	}
	if (*buf == '\0')
		strlcpy(buf, "UNKNOWN", size);
	else
		buf[strlen(buf) - 1] = '\0';
}

static int
bytes2frames(int bytes, int fmt)
{
	int enc, ch, samplesz;

	enc = fmt & 0xf00fffff;
	ch = (fmt & 0x07f00000) >> 20;
	/* Add the channel extension if present (e.g 2.1). */
	ch += (fmt & 0x08000000) >> 27;

	if (enc & (AFMT_S8 | AFMT_U8 | AFMT_MU_LAW | AFMT_A_LAW))
		samplesz = 1;
	else if (enc & (AFMT_S16_NE | AFMT_U16_NE))
		samplesz = 2;
	else if (enc & (AFMT_S24_NE | AFMT_U24_NE))
		samplesz = 3;
	else if (enc & (AFMT_S32_NE | AFMT_U32_NE))
		samplesz = 4;
	else
		samplesz = 0;

	if (!samplesz || !ch)
		return (-1);

	return (bytes / (samplesz * ch));
}

static struct audio_dev *
read_dev(char *path)
{
	nvlist_t *nvl;
	const nvlist_t * const *di;
	const nvlist_t * const *cdi;
	struct sndstioc_nv_arg arg;
	struct audio_dev *dp = NULL;
	struct audio_chan *ch;
	size_t nitems, nchans, i, j;
	int fd, caps, unit;

	if ((fd = open("/dev/sndstat", O_RDONLY)) < 0)
		err(1, "open(/dev/sndstat)");

	if (ioctl(fd, SNDSTIOC_REFRESH_DEVS, NULL) < 0)
		err(1, "ioctl(SNDSTIOC_REFRESH_DEVS)");

	arg.nbytes = 0;
	arg.buf = NULL;
	if (ioctl(fd, SNDSTIOC_GET_DEVS, &arg) < 0)
		err(1, "ioctl(SNDSTIOC_GET_DEVS#1)");

	if ((arg.buf = malloc(arg.nbytes)) == NULL)
		err(1, "malloc");

	if (ioctl(fd, SNDSTIOC_GET_DEVS, &arg) < 0)
		err(1, "ioctl(SNDSTIOC_GET_DEVS#2)");

	if ((nvl = nvlist_unpack(arg.buf, arg.nbytes, 0)) == NULL)
		err(1, "nvlist_unpack");

	if (nvlist_empty(nvl) || !nvlist_exists(nvl, SNDST_DSPS))
		errx(1, "no soundcards attached");

	if (path == NULL || (path != NULL && strcmp(basename(path), "dsp") == 0))
		unit = mixer_get_dunit();
	else
		unit = -1;

	/* Find whether the requested device exists */
	di = nvlist_get_nvlist_array(nvl, SNDST_DSPS, &nitems);
	for (i = 0; i < nitems; i++) {
		if (unit == -1 && strcmp(basename(path),
		    nvlist_get_string(di[i], SNDST_DSPS_DEVNODE)) == 0)
			break;
		else if (nvlist_exists(di[i], SNDST_DSPS_PROVIDER_INFO) &&
		    (int)nvlist_get_number(nvlist_get_nvlist(di[i],
		    SNDST_DSPS_PROVIDER_INFO), SNDST_DSPS_SOUND4_UNIT) == unit)
			break;;
	}
	if (i == nitems)
		errx(1, "device not found");

#define NV(type, item)	\
	nvlist_get_ ## type (di[i], SNDST_DSPS_ ## item)
	if ((dp = calloc(1, sizeof(struct audio_dev))) == NULL)
		err(1, "calloc");

	dp->unit = -1;
	strlcpy(dp->name, NV(string, NAMEUNIT), sizeof(dp->name));
	strlcpy(dp->desc, NV(string, DESC), sizeof(dp->desc));
	strlcpy(dp->devnode, NV(string, DEVNODE), sizeof(dp->devnode));
	dp->from_user = NV(bool, FROM_USER);
	dp->play.hwchans = NV(number, PCHAN);
	dp->rec.hwchans = NV(number, RCHAN);
#undef NV

	if (dp->play.hwchans && !nvlist_exists(di[i], SNDST_DSPS_INFO_PLAY))
		errx(1, "playback channel list empty");
	if (dp->rec.hwchans && !nvlist_exists(di[i], SNDST_DSPS_INFO_REC))
		errx(1, "recording channel list empty");

#define NV(type, mode, item)						\
	nvlist_get_ ## type (nvlist_get_nvlist(di[i],			\
	    SNDST_DSPS_INFO_ ## mode), SNDST_DSPS_INFO_ ## item)
	if (dp->play.hwchans) {
		dp->play.min_rate = NV(number, PLAY, MIN_RATE);
		dp->play.max_rate = NV(number, PLAY, MAX_RATE);
		dp->play.min_chn = NV(number, PLAY, MIN_CHN);
		dp->play.max_chn = NV(number, PLAY, MAX_CHN);
		fmt2str(dp->play.formats, sizeof(dp->play.formats),
		    NV(number, PLAY, FORMATS));
	}
	if (dp->rec.hwchans) {
		dp->rec.min_rate = NV(number, REC, MIN_RATE);
		dp->rec.max_rate = NV(number, REC, MAX_RATE);
		dp->rec.min_chn = NV(number, REC, MIN_CHN);
		dp->rec.max_chn = NV(number, REC, MAX_CHN);
		fmt2str(dp->rec.formats, sizeof(dp->rec.formats),
		    NV(number, REC, FORMATS));
	}
#undef NV

	/*
	 * Skip further parsing if the provider is not sound(4), as the
	 * following code is sound(4)-specific.
	 */
	if (strcmp(nvlist_get_string(di[i], SNDST_DSPS_PROVIDER),
	    SNDST_DSPS_SOUND4_PROVIDER) != 0)
		goto done;

	if (!nvlist_exists(di[i], SNDST_DSPS_PROVIDER_INFO))
		errx(1, "provider_info list empty");

#define NV(type, item)							\
	nvlist_get_ ## type (nvlist_get_nvlist(di[i],			\
	    SNDST_DSPS_PROVIDER_INFO), SNDST_DSPS_SOUND4_ ## item)
	strlcpy(dp->status, NV(string, STATUS), sizeof(dp->status));
	dp->unit = NV(number, UNIT);
	dp->bitperfect = NV(bool, BITPERFECT);
	dp->play.vchans = NV(number, PVCHAN);
	dp->play.vchanrate = NV(number, PVCHANRATE);
	fmt2str(dp->play.vchanformat, sizeof(dp->play.vchanformat),
	    NV(number, PVCHANFORMAT));
	dp->rec.vchans = NV(number, RVCHAN);
	dp->rec.vchanrate = NV(number, RVCHANRATE);
	fmt2str(dp->rec.vchanformat, sizeof(dp->rec.vchanformat),
	    NV(number, RVCHANFORMAT));
#undef NV

	if (!nvlist_exists(nvlist_get_nvlist(di[i],
	    SNDST_DSPS_PROVIDER_INFO), SNDST_DSPS_SOUND4_CHAN_INFO))
		errx(1, "channel info list empty");

	cdi = nvlist_get_nvlist_array(
	    nvlist_get_nvlist(di[i], SNDST_DSPS_PROVIDER_INFO),
	    SNDST_DSPS_SOUND4_CHAN_INFO, &nchans);

	TAILQ_INIT(&dp->chans);
	caps = 0;
	for (j = 0; j < nchans; j++) {
#define NV(type, item)	\
	nvlist_get_ ## type (cdi[j], SNDST_DSPS_SOUND4_CHAN_ ## item)
		if ((ch = calloc(1, sizeof(struct audio_chan))) == NULL)
			err(1, "calloc");

		strlcpy(ch->name, NV(string, NAME), sizeof(ch->name));
		strlcpy(ch->parentchan, NV(string, PARENTCHAN),
		    sizeof(ch->parentchan));
		ch->unit = NV(number, UNIT);
		cap2str(ch->caps, sizeof(ch->caps), NV(number, CAPS));
		ch->latency = NV(number, LATENCY);
		ch->rate = NV(number, RATE);
		fmt2str(ch->format, sizeof(ch->format), NV(number, FORMAT));
		ch->pid = NV(number, PID);
		strlcpy(ch->proc, NV(string, COMM), sizeof(ch->proc));
		ch->interrupts = NV(number, INTR);
		ch->xruns = NV(number, XRUNS);
		ch->feedcount = NV(number, FEEDCNT);
		ch->volume = NV(number, LEFTVOL) |
		    NV(number, RIGHTVOL) << 8;
		fmt2str(ch->hwbuf.format, sizeof(ch->hwbuf.format),
		    NV(number, HWBUF_FORMAT));
		ch->hwbuf.size_bytes = NV(number, HWBUF_SIZE);
		ch->hwbuf.size_frames =
		    bytes2frames(ch->hwbuf.size_bytes, NV(number, HWBUF_FORMAT));
		ch->hwbuf.blksz = NV(number, HWBUF_BLKSZ);
		ch->hwbuf.blkcnt = NV(number, HWBUF_BLKCNT);
		ch->hwbuf.free = NV(number, HWBUF_FREE);
		ch->hwbuf.ready = NV(number, HWBUF_READY);
		fmt2str(ch->swbuf.format, sizeof(ch->swbuf.format),
		    NV(number, SWBUF_FORMAT));
		ch->swbuf.size_bytes = NV(number, SWBUF_SIZE);
		ch->swbuf.size_frames =
		    bytes2frames(ch->swbuf.size_bytes, NV(number, SWBUF_FORMAT));
		ch->swbuf.blksz = NV(number, SWBUF_BLKSZ);
		ch->swbuf.blkcnt = NV(number, SWBUF_BLKCNT);
		ch->swbuf.free = NV(number, SWBUF_FREE);
		ch->swbuf.ready = NV(number, SWBUF_READY);
		strlcpy(ch->feederchain, NV(string, FEEDERCHAIN),
		    sizeof(ch->feederchain));
		ch->dev = dp;

		caps |= NV(number, CAPS);
		TAILQ_INSERT_TAIL(&dp->chans, ch, next);
#undef NV
	}
	cap2str(dp->caps, sizeof(dp->caps), caps);

done:
	free(arg.buf);
	nvlist_destroy(nvl);
	close(fd);

	return (dp);
}

static void
free_dev(struct audio_dev *dp)
{
	struct audio_chan *ch;

	while (!TAILQ_EMPTY(&dp->chans)) {
		ch = TAILQ_FIRST(&dp->chans);
		TAILQ_REMOVE(&dp->chans, ch, next);
		free(ch);
	}
	free(dp);
}

static void
print_dev_ctl(struct audio_dev *dp, struct audio_ctl *ctl, bool simple,
    bool showgrp)
{
	struct audio_ctl *cp;
	size_t len;

	if (ctl->type != GRP) {
		if (simple)
			printf("%s=", ctl->name);
		else
			printf("    %-20s= ", ctl->name);
	}

	switch (ctl->type) {
	case STR:
		printf("%s\n", (char *)dp + ctl->off);
		break;
	case NUM:
		printf("%d\n", *(int *)((intptr_t)dp + ctl->off));
		break;
	case VOL:
		break;
	case GRP:
		if (!simple || !showgrp)
			break;
		for (cp = dev_ctls; cp->name != NULL; cp++) {
			len = strlen(ctl->name);
			if (strncmp(ctl->name, cp->name, len) == 0 &&
			    cp->name[len] == '.' && cp->type != GRP)
				print_dev_ctl(dp, cp, simple, showgrp);
		}
		break;
	}
}

static void
print_chan_ctl(struct audio_chan *ch, struct audio_ctl *ctl, bool simple,
    bool showgrp)
{
	struct audio_ctl *cp;
	size_t len;
	int v;

	if (ctl->type != GRP) {
		if (simple)
			printf("%s.%s=", ch->name, ctl->name);
		else
			printf("    %-20s= ", ctl->name);
	}

	switch (ctl->type) {
	case STR:
		printf("%s\n", (char *)ch + ctl->off);
		break;
	case NUM:
		printf("%d\n", *(int *)((intptr_t)ch + ctl->off));
		break;
	case VOL:
		v = *(int *)((intptr_t)ch + ctl->off);
		printf("%.2f:%.2f\n",
		    MIX_VOLNORM(v & 0x00ff), MIX_VOLNORM((v >> 8) & 0x00ff));
		break;
	case GRP:
		if (!simple || !showgrp)
			break;
		for (cp = chan_ctls; cp->name != NULL; cp++) {
			len = strlen(ctl->name);
			if (strncmp(ctl->name, cp->name, len) == 0 &&
			    cp->name[len] == '.' && cp->type != GRP)
				print_chan_ctl(ch, cp, simple, showgrp);
		}
		break;
	}
}

static void
print_dev(struct audio_dev *dp)
{
	struct audio_chan *ch;
	struct audio_ctl *ctl;

	if (!oflag) {
		printf("%s: <%s> %s", dp->name, dp->desc, dp->status);

		printf(" (");
		if (dp->play.hwchans)
			printf("play");
		if (dp->play.hwchans && dp->rec.hwchans)
			printf("/");
		if (dp->rec.hwchans)
			printf("rec");
		printf(")\n");
	}

	for (ctl = dev_ctls; ctl->name != NULL; ctl++)
		print_dev_ctl(dp, ctl, oflag, false);

	if (vflag) {
		TAILQ_FOREACH(ch, &dp->chans, next) {
			if (!oflag)
				printf("    ---\n");
			for (ctl = chan_ctls; ctl->name != NULL; ctl++)
				print_chan_ctl(ch, ctl, oflag, false);
		}
	}
}

static int
sysctl_int(char *buf, const char *arg, int *var)
{
	size_t size;
	const char *val = arg;
	int n;

	n = strtol(val, NULL, 10);
	if (errno == EINVAL || errno == ERANGE) {
		warn("strtol(%s)", val);
		return (-1);
	}

	size = sizeof(int);
	if (sysctlbyname(buf, NULL, 0, &n, size) < 0) {
		warn("sysctlbyname(%s, %d)", buf, n);
		return (-1);
	}
	if (sysctlbyname(buf, &n, &size, NULL, 0) < 0) {
		warn("sysctlbyname(%s)", buf);
		return (-1);
	}

	printf("%s: %d -> %d\n", buf, *var, n);
	*var = n;

	return (0);
}

static int
sysctl_str(char *buf, const char *arg, char *var, size_t varsz)
{
	size_t size;
	const char *val = arg;
	char *tmp;

	size = strlen(val);
	if (sysctlbyname(buf, NULL, 0, val, size) < 0) {
		warn("sysctlbyname(%s, %s)", buf, val);
		return (-1);
	}
	if (sysctlbyname(buf, NULL, &size, NULL, 0) < 0) {
		warn("sysctlbyname(%s)", buf);
		return (-1);
	}
	if ((tmp = calloc(1, size)) == NULL)
		err(1, "calloc");
	if (sysctlbyname(buf, tmp, &size, NULL, 0) < 0) {
		warn("sysctlbyname(%s)", buf);
		free(tmp);
		return (-1);
	}

	printf("%s: %s -> %s\n", buf, var, tmp);
	strlcpy(var, tmp, varsz);
	free(tmp);

	return (0);
}

static int
mod_bitperfect(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.bitperfect", dp->unit);

	return (sysctl_int(buf, arg, &dp->bitperfect));
}

static int
mod_play_vchans(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.play.vchans", dp->unit);

	return (sysctl_int(buf, arg, &dp->play.vchans));
}

static int
mod_play_vchanrate(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.play.vchanrate", dp->unit);

	return (sysctl_int(buf, arg, &dp->play.vchanrate));
}

static int
mod_play_vchanformat(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.play.vchanformat", dp->unit);

	return (sysctl_str(buf, arg, dp->play.vchanformat,
	    sizeof(dp->play.vchanformat)));
}

static int
mod_rec_vchans(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.rec.vchans", dp->unit);

	return (sysctl_int(buf, arg, &dp->rec.vchans));
}

static int
mod_rec_vchanrate(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.rec.vchanrate", dp->unit);

	return (sysctl_int(buf, arg, &dp->rec.vchanrate));
}

static int
mod_rec_vchanformat(struct audio_dev *dp, void *arg)
{
	char buf[64];

	if (dp->from_user)
		return (-1);

	snprintf(buf, sizeof(buf), "dev.pcm.%d.rec.vchanformat", dp->unit);

	return (sysctl_str(buf, arg, dp->rec.vchanformat,
	    sizeof(dp->rec.vchanformat)));
}

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: %s [-f file] [-ov] [control[=value] ...]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct audio_dev *dp;
	struct audio_chan *ch;
	struct audio_ctl *ctl;
	char *path = NULL;
	char *s, *propstr;
	bool show = true, found;
	int c;

	while ((c = getopt(argc, argv, "f:ov")) != -1) {
		switch (c) {
		case 'f':
			path = optarg;
			break;
		case 'o':
			oflag = true;
			break;
		case 'v':
			vflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	dp = read_dev(path);

	while (argc > 0) {
		if ((s = strdup(*argv)) == NULL)
			err(1, "strdup(%s)", *argv);

		propstr = strsep(&s, "=");
		if (propstr == NULL)
			goto next;

		found = false;
		for (ctl = dev_ctls; ctl->name != NULL; ctl++) {
			if (strcmp(ctl->name, propstr) != 0)
				continue;
			if (s == NULL) {
				print_dev_ctl(dp, ctl, true, true);
				show = false;
			} else if (ctl->mod != NULL && ctl->mod(dp, s) < 0)
				warnx("%s(%s) failed", ctl->name, s);
			found = true;
			break;
		}
		if (vflag) {
			TAILQ_FOREACH(ch, &dp->chans, next) {
				for (ctl = chan_ctls; ctl->name != NULL; ctl++) {
					if (strcmp(ctl->name, propstr) != 0)
						continue;
					print_chan_ctl(ch, ctl, true, true);
					show = false;
					found = true;
					break;
				}
			}
		}
		if (!found)
			warnx("%s: no such property", propstr);
next:
		free(s);
		argc--;
		argv++;
	}

	/* XXX do we want this behavior? */
	if (show)
		print_dev(dp);
	free_dev(dp);

	return (0);
}
