//Copyright (C) 2016 Realtek Semiconductor Corporation.

#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/rawmidi.h>
#include <sound/initval.h>
#include <linux/mutex.h>
#include <linux/ioctl.h> /* needed for the _IOW etc stuff used later */
#include <linux/syscalls.h> /* needed for the _IOW etc stuff used later */
#include <linux/mpage.h>
#include <linux/dcache.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>
#include <sound/asound.h>
#include <sound/compress_driver.h>
#include <asm/cacheflush.h>
#include "snd-realtek.h"
#include "snd-realtek-compress.h"

extern struct ion_client *alsa_client;
static struct ion_handle *rtk_compress_handle;
static struct ion_handle *compr_inRing_handle;
static struct ion_handle *compr_inband_handle;
static struct ion_handle *compr_dwnstrm_handle;
static struct ion_handle *compr_outRing_handle[8];
static struct ion_handle *refclock_handle;

static struct ion_handle *rawdelay_handle = NULL;
static int *rawdelay_mem = NULL;
static ion_phys_addr_t phy_rawdelay = 0;

//#define DEC_IN_BUFFER_SIZE       (128 * 1024)
#define DEC_OUT_BUFFER_SIZE      (36 * 1024)
#define DEC_INBAND_BUFFER_SIZE   (16 * 1024)
#define DEC_DWNSTRM_BUFFER_SIZE  (32 * 1024)

#define AUDIO_DEC_OUTPIN         8

#define NUM_CODEC                7
#define MIN_FRAGMENT             2
#define MAX_FRAGMENT             4
#define MIN_FRAGMENT_SIZE        (1024) //(50 * 1024)
#define MAX_FRAGMENT_SIZE        (8192*64) //(1024 * 1024)

#define RAWDELAY_MEM_SIZE        8

typedef struct rtk_runtime_stream {
    //RTK_snd_card_t *card;
    //struct snd_compr_stream* cstream;
    int audioDecId;
    int audioPPId;
    int audioOutId;
    int audioDecPinId;
    int audioAppPinId;

    unsigned int audioChannel;
    unsigned int audioSamplingRate;
    bool isGetInfo;

    int status;
    size_t bytes_written;
    size_t copied_total;
    unsigned long outFrames;
//    unsigned long preOutFrames;

    // ringbuffer header
    RINGBUFFER_HEADER decInRingHeader;
    RINGBUFFER_HEADER decInbandRingHeader;
    RINGBUFFER_HEADER dwnstrmRingHeader;
    RINGBUFFER_HEADER decOutRingHeader[8];

    //virtual address of ringbuffer
    unsigned char* virDecInRing;
    unsigned char* virInbandRing;
    unsigned char* virDwnRing;
    unsigned char* virDecOutRing[8];

    unsigned char* virDwnRingLower;
    unsigned char* virDwnRingUpper;

    unsigned char* virDecOutRingLower[8];
    unsigned char* virDecOutRingUpper[8];

    //physical address of ringbuffer
    ion_phys_addr_t phyDecInRing;
    ion_phys_addr_t phyDecInbandRing;
    ion_phys_addr_t phyDecDwnstrmRing;
    ion_phys_addr_t phyDecOutRing[8];

    REFCLOCK* refclock;
    ion_phys_addr_t phyRefclock;

    ion_phys_addr_t phy_addr;
} rtk_runtime_stream_t;

typedef enum {
    BS,
    COMMAND
} DELIVER_WHAT;

unsigned long reverseInteger(unsigned long value) {
    unsigned long b0 = value & 0x000000ff;
    unsigned long b1 = (value & 0x0000ff00) >> 8;
    unsigned long b2 = (value & 0x00ff0000) >> 16;
    unsigned long b3 = (value & 0xff000000) >> 24;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

void pli_IPCCopyMemory(unsigned char* src, unsigned char* des, unsigned long len) {
#if 0
    unsigned long i;
    unsigned long *psrc, *pdes;

    if ((((unsigned long)src & 0x3) != 0) || (((unsigned long)des & 0x3) != 0) || ((len & 0x3) != 0))
        TRACE_CODE("error in pli_IPCCopyMemory()...\n");

    for (i = 0; i < len; i+=4) {
        psrc = (unsigned long *)&src[i];
        pdes = (unsigned long *)&des[i];
        *pdes = reverseInteger(*psrc);
        //TRACE_CODE("%x, %x...\n", src[i], des[i]);
    }
#else
    volatile unsigned char * pdes = (volatile unsigned char *) des;
    volatile unsigned char * psrc = (volatile unsigned char *) src;
    int i;
    //printk("[%s] des:%p src:%p size:%lu\n", __func__, des, src, len);
    for (i = 0; i < len; i+=4)
        writel(__cpu_to_be32(readl(&psrc[i])), &pdes[i]);
#endif
}

void MyMemcpy(DELIVER_WHAT type, unsigned char *pSrc, unsigned char *pDes, long size) {
    if (type == COMMAND) {
        pli_IPCCopyMemory(pSrc, pDes, size);
    }
    else {
        memcpy(pDes, pSrc, size);
    }
}

unsigned long GetBufferFromRing(unsigned char* upper, unsigned char* lower, unsigned char* rptr, unsigned char* dest, unsigned long size) {
    unsigned long space = 0;
    if (rptr + size < upper) {
        MyMemcpy(COMMAND, rptr, dest, size);
    } else {
        space = upper - rptr;
        //ALOGD("wrap around space %u\n", space);
        MyMemcpy(COMMAND, rptr, dest, space);
        if(size > space)
            MyMemcpy(COMMAND, lower, dest + space, size - space);
    }
    return space;
}

void UpdateRingPtr(unsigned char* upper, unsigned char* lower, unsigned char* rptr,
    rtk_runtime_stream_t *stream, unsigned long size, unsigned long space) {
    //TRACE_CODE("%s %d rptr %x size %d upper %x\n", __FUNCTION__, __LINE__, rptr, size, upper);
    if ((rptr + size) < upper) {
        stream->dwnstrmRingHeader.readPtr[0] = ntohl(ntohl(stream->dwnstrmRingHeader.readPtr[0]) + size);
        //TRACE_CODE("%s %d rp %x\n", __FUNCTION__, __LINE__, stream->virDwnRing + (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr)));
    } else {
        stream->dwnstrmRingHeader.readPtr[0] = ntohl(ntohl(stream->dwnstrmRingHeader.beginAddr) + size - space);
        //TRACE_CODE("%s %d rp %x\n", __FUNCTION__, __LINE__, stream->virDwnRing + (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr)));
    }
}

static long ringValidData(long ring_base, long ring_limit, long ring_rp, long ring_wp) {
    if (ring_wp >= ring_rp) {
        return (ring_wp - ring_rp);
    } else {
        return (ring_limit - ring_base) - (ring_rp - ring_wp);
    }
}

static long validFreeSize(long base, long limit, long rp, long wp) {
    return (limit - base) - ringValidData(base, limit, rp, wp) - 1;
}

long GetGeneralInstanceID(long instanceID, long pinID) {
    return ((instanceID & 0xFFFFF000) | (pinID & 0xFFF));
}

int triggerAudio(rtk_runtime_stream_t *stream, int cmd) {
    //TRACE_CODE("%s %d", __FUNCTION__, __LINE__);
    switch (cmd) {
        case SNDRV_PCM_TRIGGER_START:
        case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
            if (stream->status != SNDRV_PCM_TRIGGER_START) {
                RPC_TOAGENT_RUN_SVC(stream->audioOutId);
                RPC_TOAGENT_RUN_SVC(GetGeneralInstanceID(stream->audioPPId, stream->audioAppPinId));
                RPC_TOAGENT_RUN_SVC(stream->audioDecId);
            }
            stream->status = SNDRV_PCM_TRIGGER_START;
            break;
        case SNDRV_PCM_TRIGGER_STOP:
            if (stream->status != SNDRV_PCM_TRIGGER_STOP) {
                RPC_TOAGENT_STOP_SVC(stream->audioOutId);
                RPC_TOAGENT_STOP_SVC(GetGeneralInstanceID(stream->audioPPId, stream->audioAppPinId));
                RPC_TOAGENT_STOP_SVC(stream->audioDecId);
            }
            stream->status = SNDRV_PCM_TRIGGER_STOP;
            break;
        case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
            if (stream->status != SNDRV_PCM_TRIGGER_PAUSE_PUSH) {
                RPC_TOAGENT_PAUSE_SVC(stream->audioOutId);
                RPC_TOAGENT_PAUSE_SVC(GetGeneralInstanceID(stream->audioPPId, stream->audioAppPinId));
                RPC_TOAGENT_PAUSE_SVC(stream->audioDecId);
            }
            stream->refclock->RCD = -1;
            stream->status = SNDRV_PCM_TRIGGER_PAUSE_PUSH;
            break;
        default:
            break;
    }

    return 0;
}

void destroyAudioComponent(rtk_runtime_stream_t *stream) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    triggerAudio(stream, SNDRV_PCM_TRIGGER_STOP);

    RPC_TOAGENT_PP_INIT_PIN_SVC(GetGeneralInstanceID(stream->audioPPId, stream->audioAppPinId));
    RPC_TOAGENT_DESTROY_SVC(GetGeneralInstanceID(stream->audioPPId, stream->audioAppPinId));
    RPC_TOAGENT_DESTROY_SVC(stream->audioDecId);

    stream->audioDecId = 0;
    stream->audioPPId = 0;
    stream->audioOutId = 0;
    stream->audioDecPinId = 0;
    stream->audioAppPinId = 0;
}

int createAudioComponent(rtk_runtime_stream_t *stream) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    // create decoder agent
    if (RPC_TOAGENT_CREATE_DECODER_AGENT(&stream->audioDecId, &stream->audioDecPinId)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        return -ENOMEM;
    }

    // create pp agent and get global pp pin
    if (RPC_TOAGENT_CREATE_PP_AGENT(&stream->audioPPId, &stream->audioAppPinId)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        return -ENOMEM;
    }

    // create ao agent
    if (RPC_TOAGENT_CREATE_AO_AGENT(&stream->audioOutId, AUDIO_OUT)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        return -ENOMEM;
    }
    stream->audioOutId = GetGeneralInstanceID(stream->audioOutId, stream->audioAppPinId);
    ////////////////////////////////////////////////////////////
    /// SEND RPC tell 5280 audio fw OMX AUDIO VERSION
    ////////////////////////////////////////////////////////////
    //yllin: add this to handle incompatible issue casued by OMX use new AUDIO_INFO_CHANNEL_INDEX and audio fw enable PP_SUPPORT_INBAND_QUEUE.
    //ENUM_OMX_AUDIO_VERSION_0 : supports only old AUDIO_INFO_CHANNEL_INDEX type(contains 'char' type)
    //ENUM_OMX_AUDIO_VERSION_1 : supports both new(contains only 'long' type) & old AUDIO_INFO_CHANNEL_INDEX type.

    if (RPC_TOAGENT_SEND_AUDIO_VERSION(ENUM_OMX_AUDIO_VERSION_1)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        return -ENOMEM;
    }

    TRACE_CODE("[create audio dec %d pin id %d]\n", stream->audioDecId, stream->audioDecPinId);
    TRACE_CODE("[create audio pp  %d pin id %d]\n", stream->audioPPId, stream->audioAppPinId);
    TRACE_CODE("[create audio out %d]\n", stream->audioOutId);
    return 0;
}

int configOutput(rtk_runtime_stream_t *stream) {
    //config i2s
    AUDIO_CONFIG_DAC_I2S dac_i2s_config;
    AUDIO_CONFIG_DAC_SPDIF dac_spdif_config;
    AUDIO_RPC_REFCLOCK audioRefClock;
    AUDIO_RPC_FOCUS focus;
    size_t len;

    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    dac_i2s_config.instanceID = stream->audioOutId;
    dac_i2s_config.dacConfig.audioGeneralConfig.interface_en = 1;
    dac_i2s_config.dacConfig.audioGeneralConfig.channel_out = LEFT_CENTER_FRONT_CHANNEL_EN|RIGHT_CENTER_FRONT_CHANNEL_EN;
    dac_i2s_config.dacConfig.audioGeneralConfig.count_down_play_en = 0;
    dac_i2s_config.dacConfig.audioGeneralConfig.count_down_play_cyc = 0;
    dac_i2s_config.dacConfig.sampleInfo.sampling_rate = 48000;
    dac_i2s_config.dacConfig.sampleInfo.PCM_bitnum = 24;
    if (RPC_TOAGENT_DAC_I2S_CONFIG(&dac_i2s_config)) {
        ALSA_WARNING("[%s %d]\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //config spdif
    dac_spdif_config.instanceID = stream->audioOutId;
    dac_spdif_config.spdifConfig.audioGeneralConfig.interface_en = 1;
    dac_spdif_config.spdifConfig.audioGeneralConfig.channel_out = SPDIF_LEFT_CHANNEL_EN|SPDIF_RIGHT_CHANNEL_EN;
    dac_spdif_config.spdifConfig.audioGeneralConfig.count_down_play_en = 0;
    dac_spdif_config.spdifConfig.audioGeneralConfig.count_down_play_cyc = 0;
    dac_spdif_config.spdifConfig.sampleInfo.sampling_rate = 48000;
    dac_spdif_config.spdifConfig.sampleInfo.PCM_bitnum = 24;
    dac_spdif_config.spdifConfig.out_cs_info.non_pcm_valid = 0;
    dac_spdif_config.spdifConfig.out_cs_info.non_pcm_format = 0;
    dac_spdif_config.spdifConfig.out_cs_info.audio_format = 0;
    dac_spdif_config.spdifConfig.out_cs_info.spdif_consumer_use = 0;
    dac_spdif_config.spdifConfig.out_cs_info.copy_right = 0;
    dac_spdif_config.spdifConfig.out_cs_info.pre_emphasis = 0;
    dac_spdif_config.spdifConfig.out_cs_info.stereo_channel = 0;
    if (RPC_TOAGENT_DAC_SPDIF_CONFIG(&dac_spdif_config)) {
        ALSA_WARNING("[%s %d]\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //set refclock
    refclock_handle = ion_alloc(alsa_client, sizeof(stream->refclock), 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);
    if (IS_ERR(refclock_handle)) {
        ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
        return -1;
    }
    if (ion_phys(alsa_client, refclock_handle, &stream->phyRefclock, &len) != 0) {
        ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
        return -1;
    }
    stream->refclock = (REFCLOCK*)ion_map_kernel(alsa_client, refclock_handle);
    memset(stream->refclock, 0, sizeof(len));
    stream->refclock->mastership.systemMode = AVSYNC_FORCED_SLAVE;
    stream->refclock->mastership.audioMode = AVSYNC_FORCED_MASTER;
    stream->refclock->mastership.videoMode = AVSYNC_FORCED_SLAVE;
    stream->refclock->mastership.masterState = AVSYNC_FORCED_SLAVE;
    stream->refclock->videoFreeRunThreshold = htonl(0x7FFFFFFF);
    stream->refclock->audioFreeRunThreshold = htonl(0x7FFFFFFF);

    audioRefClock.instanceID = stream->audioOutId;
    audioRefClock.pRefClockID = stream->audioAppPinId;
    audioRefClock.pRefClock = (long)stream->phyRefclock;

    if (RPC_TOAGENT_SETREFCLOCK(&audioRefClock)) {
        ALSA_WARNING("[%s %d]\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //set focus
    focus.instanceID = stream->audioOutId;
    focus.focusID = 0;
    if (RPC_TOAGENT_SWITCH_FOCUS(&focus)) {
        ALSA_WARNING("[%s %d]\n", __FUNCTION__, __LINE__);
        return -1;
    }
    focus.instanceID = stream->audioPPId;
    focus.focusID = stream->audioAppPinId;
    if (RPC_TOAGENT_SWITCH_FOCUS(&focus)) {
        ALSA_WARNING("[%s %d]\n", __FUNCTION__, __LINE__);
        return -1;
    }
    return 0;
}

void destroyRingBuf(rtk_runtime_stream_t *stream) {
    //TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    if (alsa_client != NULL) {
        int ch;

        if (refclock_handle != NULL) {
            //TRACE_CODE("%s %d free refclock_handle\n", __FUNCTION__, __LINE__);
            ion_unmap_kernel(alsa_client, refclock_handle);
            ion_free(alsa_client, refclock_handle);
            refclock_handle = NULL;
        }

        if (compr_inRing_handle != NULL) {
            //TRACE_CODE("%s %d free compr_inRing_handle\n", __FUNCTION__, __LINE__);
            ion_unmap_kernel(alsa_client, compr_inRing_handle);
            ion_free(alsa_client, compr_inRing_handle);
            compr_inRing_handle = NULL;
        }

        if (compr_inband_handle != NULL) {
            //TRACE_CODE("%s %d free compr_inband_handle\n", __FUNCTION__, __LINE__);
            ion_unmap_kernel(alsa_client, compr_inband_handle);
            ion_free(alsa_client, compr_inband_handle);
            compr_inband_handle = NULL;
        }

        if (compr_dwnstrm_handle != NULL) {
            //TRACE_CODE("%s %d free compr_dwnstrm_handle\n", __FUNCTION__, __LINE__);
            ion_unmap_kernel(alsa_client, compr_dwnstrm_handle);
            ion_free(alsa_client, compr_dwnstrm_handle);
            compr_dwnstrm_handle = NULL;
        }

        if (compr_outRing_handle[0] != NULL) {
            //TRACE_CODE("%s %d free compr_outRing_handle\n", __FUNCTION__, __LINE__);
            for (ch = 0; ch < AUDIO_DEC_OUTPIN; ch++) {
                ion_unmap_kernel(alsa_client, compr_outRing_handle[ch]);
                ion_free(alsa_client, compr_outRing_handle[ch]);
                compr_outRing_handle[ch] = NULL;
            }
        }
    }
}

int createRingBuf(rtk_runtime_stream_t *stream, unsigned int buffer_size) {

    int ch, i;
    ion_phys_addr_t dat;
    size_t len;
    AUDIO_RPC_RINGBUFFER_HEADER ringBufferHeader;
    AUDIO_RPC_CONNECTION connection;

    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    //create RINGBUFFER_HEADER decInRing
    compr_inRing_handle = ion_alloc(alsa_client, buffer_size, 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);
    if (IS_ERR(compr_inRing_handle)) {
        ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    if (ion_phys(alsa_client, compr_inRing_handle, &dat, &len) != 0) {
        ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    stream->virDecInRing = ion_map_kernel(alsa_client, compr_inRing_handle);
    stream->phyDecInRing = dat;

    //TRACE_CODE("decInring phy %x limit %x\n\n", stream->phyDecInRing, stream->phyDecInRing + len);

    TRACE_CODE("%s %d inRing_size %u\n", __FUNCTION__, __LINE__,buffer_size);
    stream->decInRingHeader.beginAddr = htonl((unsigned long)stream->phyDecInRing);
    stream->decInRingHeader.size = htonl(buffer_size);
    stream->decInRingHeader.writePtr = stream->decInRingHeader.beginAddr;
    stream->decInRingHeader.numOfReadPtr = htonl(1);
    stream->decInRingHeader.readPtr[0] = stream->decInRingHeader.beginAddr;

    ringBufferHeader.instanceID = stream->audioDecId;
    ringBufferHeader.pinID = BASE_BS_IN; //stream->audioDecPinId;
    ringBufferHeader.readIdx = 0;
    ringBufferHeader.listSize = 1;
    ringBufferHeader.pRingBufferHeaderList[0] = (unsigned long)&stream->decInRingHeader - (unsigned long)stream + stream->phy_addr;

    if (RPC_TOAGENT_INITRINGBUFFER_HEADER_SVC(&ringBufferHeader, ringBufferHeader.listSize) < 0) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };
    //TRACE_CODE("decInRing wp %x rp %x\n\n", htonl(stream->decInRingHeader.writePtr), htonl(stream->decInRingHeader.readPtr[0]));

    //create RINGBUFFER_HEADER decInbandRing;
    compr_inband_handle = ion_alloc(alsa_client, DEC_INBAND_BUFFER_SIZE, 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);
    if (IS_ERR(compr_inband_handle)) {
        ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    if (ion_phys(alsa_client, compr_inband_handle, &dat, &len) != 0) {
        ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    stream->virInbandRing = ion_map_kernel(alsa_client, compr_inband_handle);
    stream->phyDecInbandRing = dat;

    stream->decInbandRingHeader.beginAddr = htonl((unsigned long)stream->phyDecInbandRing);
    stream->decInbandRingHeader.size = htonl(DEC_INBAND_BUFFER_SIZE);
    stream->decInbandRingHeader.writePtr = stream->decInbandRingHeader.beginAddr;
    stream->decInbandRingHeader.numOfReadPtr = htonl(1);
    stream->decInbandRingHeader.readPtr[0] = stream->decInbandRingHeader.beginAddr;

    ringBufferHeader.instanceID = stream->audioDecId;
    ringBufferHeader.pinID = INBAND_QUEUE;
    ringBufferHeader.readIdx = 0;
    ringBufferHeader.listSize = 1;
    ringBufferHeader.pRingBufferHeaderList[0] = (unsigned long)&stream->decInbandRingHeader - (unsigned long)stream + stream->phy_addr;

    if (RPC_TOAGENT_INITRINGBUFFER_HEADER_SVC(&ringBufferHeader, ringBufferHeader.listSize) < 0) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };

    //create RINGBUFFER_HEADER dwnstrmRing;
    compr_dwnstrm_handle = ion_alloc(alsa_client, DEC_DWNSTRM_BUFFER_SIZE, 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);
    if (IS_ERR(compr_dwnstrm_handle)) {
        ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    if (ion_phys(alsa_client, compr_dwnstrm_handle, &dat, &len) != 0) {
        ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
        goto fail;
    }
    stream->virDwnRing = ion_map_kernel(alsa_client, compr_dwnstrm_handle);
    stream->phyDecDwnstrmRing = dat;

    stream->virDwnRingLower = stream->virDwnRing;
    stream->virDwnRingUpper = stream->virDwnRing + DEC_DWNSTRM_BUFFER_SIZE;

    stream->dwnstrmRingHeader.beginAddr = htonl((unsigned long)stream->phyDecDwnstrmRing);
    stream->dwnstrmRingHeader.size = htonl(DEC_DWNSTRM_BUFFER_SIZE);
    stream->dwnstrmRingHeader.writePtr = stream->dwnstrmRingHeader.beginAddr;
    stream->dwnstrmRingHeader.numOfReadPtr = htonl(1);
    stream->dwnstrmRingHeader.readPtr[0] = stream->dwnstrmRingHeader.beginAddr;

    ringBufferHeader.instanceID = stream->audioDecId;
    ringBufferHeader.pinID = DWNSTRM_INBAND_QUEUE;
    ringBufferHeader.readIdx = -1;
    ringBufferHeader.listSize = 1;
    ringBufferHeader.pRingBufferHeaderList[0] = (unsigned long)&stream->dwnstrmRingHeader - (unsigned long)stream + stream->phy_addr;

    if (RPC_TOAGENT_INITRINGBUFFER_HEADER_SVC(&ringBufferHeader, ringBufferHeader.listSize) < 0) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };

    //create RINGBUFFER_HEADER decOutRing[8];
    for (ch = 0; ch < AUDIO_DEC_OUTPIN; ch++) {
        compr_outRing_handle[ch] = ion_alloc(alsa_client, DEC_OUT_BUFFER_SIZE, 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);
        if (IS_ERR(compr_outRing_handle[ch])) {
            ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
            goto fail;
        }
        if (ion_phys(alsa_client, compr_outRing_handle[ch], &dat, &len) != 0) {
            ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
            goto fail;
        }
        stream->virDecOutRing[ch] = ion_map_kernel(alsa_client, compr_outRing_handle[ch]);
        stream->phyDecOutRing[ch] = dat;

        stream->virDecOutRingLower[ch] = stream->virDecOutRing[ch];
        stream->virDecOutRingUpper[ch] = stream->virDecOutRing[ch] + DEC_OUT_BUFFER_SIZE;

        stream->decOutRingHeader[ch].beginAddr = htonl((unsigned long)stream->phyDecOutRing[ch]);
        stream->decOutRingHeader[ch].size = htonl(DEC_OUT_BUFFER_SIZE);
        stream->decOutRingHeader[ch].writePtr = stream->decOutRingHeader[ch].beginAddr;
        stream->decOutRingHeader[ch].numOfReadPtr = htonl(1);
        for (i = 0; i < 4; i++)
            stream->decOutRingHeader[ch].readPtr[i] = stream->decOutRingHeader[ch].beginAddr;
    }

    ringBufferHeader.instanceID = stream->audioDecId;
    ringBufferHeader.pinID = PCM_OUT;
    ringBufferHeader.readIdx = -1; //todo maybe be to set 1 in there for getting frame pts
//    ringBufferHeader.readIdx = 1; //todo maybe be to set 1 in there for getting frame pts
    ringBufferHeader.listSize = AUDIO_DEC_OUTPIN;
    for (ch = 0; ch < AUDIO_DEC_OUTPIN; ++ch)
        ringBufferHeader.pRingBufferHeaderList[ch] = (unsigned long)&stream->decOutRingHeader[ch] - (unsigned long)stream + stream->phy_addr;

    if (RPC_TOAGENT_INITRINGBUFFER_HEADER_SVC(&ringBufferHeader, ringBufferHeader.listSize) < 0) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };

    ringBufferHeader.instanceID = stream->audioPPId;
    ringBufferHeader.pinID = stream->audioAppPinId;
    ringBufferHeader.readIdx = 0;
    ringBufferHeader.listSize = AUDIO_DEC_OUTPIN;
    for (ch = 0; ch < AUDIO_DEC_OUTPIN; ++ch)
        ringBufferHeader.pRingBufferHeaderList[ch] = (unsigned long)&stream->decOutRingHeader[ch] - (unsigned long)stream + stream->phy_addr;

    if (RPC_TOAGENT_INITRINGBUFFER_HEADER_SVC(&ringBufferHeader, ringBufferHeader.listSize) < 0) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };

    //connection
    connection.desInstanceID = stream->audioPPId;
    connection.srcInstanceID = stream->audioDecId;
    connection.srcPinID = PCM_OUT;
    connection.desPinID = stream->audioAppPinId;

    if (RPC_TOAGENT_CONNECT_SVC(&connection)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    };

    if (configOutput(stream)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    }

    return 0;

fail:
    destroyRingBuf(stream);
    return -1;
}

int getAudioInfo(rtk_runtime_stream_t *stream, unsigned int *channel, unsigned int *rate) {
    int ret = 0;
    /*
    unsigned char* ptswp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.writePtr) - ntohl(stream->dwnstrmRingHeader.beginAddr));
    */
    unsigned char* ptsrp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));

    bool new_chIdx_type = false;
    int audio_start_thld = 0;
    AUDIO_INFO_PCM_FORMAT pcmFormat;
    AUDIO_INBAND_PRIVATE_INFO inbandInfo;

    ///////////////////////////////////////////////////////////////////////////////
    /// privateinfo   (16)
    /// pcm_format    (32)
    /// privateinfo   (16)
    /// channel_index (20)
    ///////////////////////////////////////////////////////////////////////////////
    memset(&inbandInfo, 0, INBAND_INFO_SIZE);
    GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, (unsigned char*)&inbandInfo, INBAND_INFO_SIZE);
    //TRACE_CODE("inbanInfo headerType %lu\n", inbandInfo.header.type);
    //TRACE_CODE("inbanInfo headerSize %lu\n", inbandInfo.header.size);
    //TRACE_CODE("inbanInfo infoType   %lu\n", inbandInfo.infoType);
    //TRACE_CODE("inbanInfo size       %lu\n", inbandInfo.infoSize);

    if (inbandInfo.infoType != AUDIO_INBAND_CMD_PRIVATE_PCM_FMT) {
        return ret;
    }

    memset(&pcmFormat, 0, INBAND_PCM_SIZE);
    GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp + INBAND_INFO_SIZE, (unsigned char*)&pcmFormat, INBAND_PCM_SIZE);

    //TRACE_CODE("pcmFormat chnum %d\n", pcmFormat.pcmFormat.chnum);
    TRACE_CODE("pcmFormat rate  %d\n", pcmFormat.pcmFormat.samplerate);

    memset(&inbandInfo, 0, INBAND_INFO_SIZE);
    GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp + INBAND_INFO_SIZE + INBAND_PCM_SIZE, (unsigned char*)&inbandInfo, INBAND_INFO_SIZE);

    //TRACE_CODE("cmd header type %lu\n", inbandInfo.header.type);
    //TRACE_CODE("cmd header size %lu\n", inbandInfo.header.size);
    //TRACE_CODE("cmd infoType    %lu\n", inbandInfo.infoType);
    //TRACE_CODE("cmd infoSize    %lu\n", inbandInfo.infoSize);

    if (inbandInfo.infoType != AUDIO_INBAND_CMD_PRIVATE_CH_IDX) {
        TRACE_CODE("Info.infoType != AUDIO_INBAND");
        return ret;
    }

    //get pcm information and channel index
    *rate = pcmFormat.pcmFormat.samplerate;

    if(inbandInfo.infoSize > OLD_CHANNEL_INDEX_INFO_SIZE) {
        new_chIdx_type = true;
        printk("use NEW CHANNEL_INDEX_INFO\n");
    } else {
        printk("use OLD CHANNEL_INDEX_INFO\n");
    }

    if (new_chIdx_type == true) {
        int count;
        AUDIO_INFO_CHANNEL_INDEX_NEW infoChIndex;
        memset(&infoChIndex, 0, sizeof(infoChIndex));
        GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp + 2 * INBAND_INFO_SIZE + INBAND_PCM_SIZE, (unsigned char*)&infoChIndex, sizeof(infoChIndex));

        for (count = 0; count < AUDIO_DEC_OUTPIN; count++) {
            //TRACE_CODE("infoChIndex index %d\n", infoChIndex.channel_index[count]);
            if(infoChIndex.channel_index[count])
                (*channel)++;
        }
    } else{
        int count;
        AUDIO_INFO_CHANNEL_INDEX_OLD infoChIndex;
        memset(&infoChIndex, 0, sizeof(infoChIndex));
        GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp + 2 * INBAND_INFO_SIZE + INBAND_PCM_SIZE, (unsigned char*)&infoChIndex, sizeof(infoChIndex));

        for (count = 0; count < AUDIO_DEC_OUTPIN; count++) {
            //TRACE_CODE("infoChIndex index %d\n", infoChIndex.channel_index[count]);
            if(infoChIndex.channel_index[count])
                (*channel)++;
        }
    }

    audio_start_thld = INBAND_PCM_SIZE + (2 * INBAND_INFO_SIZE) + inbandInfo.infoSize;
    stream->dwnstrmRingHeader.readPtr[0] = ntohl(ntohl(stream->dwnstrmRingHeader.readPtr[0]) + audio_start_thld);

    ret = 1;
    return ret;
}

int checkAudioInfo(rtk_runtime_stream_t *stream) {
    int ret = 0;

    unsigned char* ptswp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.writePtr) - ntohl(stream->dwnstrmRingHeader.beginAddr));
    unsigned char* ptsrp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));

    if ((ptswp - ptsrp) >= AUDIO_START_THRES) {
        unsigned int numChannel = 0;
        unsigned int numRate = 0;
        ret = getAudioInfo(stream, &numChannel, &numRate);

        if (numChannel > 0) {
            TRACE_CODE("[RTK Codec] nChannels      %u\n", numChannel);
            TRACE_CODE("[RTK Codec] nSamplesPerSec %u\n", numRate);
            stream->isGetInfo = true;
            if( numChannel != stream->audioChannel || numRate != stream->audioSamplingRate) {
                TRACE_CODE("[RTK] INFO CHANGE\n");
                stream->audioChannel = numChannel;
                stream->audioSamplingRate = numRate;
            }
            ret = 1;
        }
    }
    return ret;
}

int GetSampleIndex(unsigned int sampleRate) {
    unsigned int index;
    static const unsigned int aac_samplerate_tab[12] = {
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000};

    for (index = 0; index < sizeof(aac_samplerate_tab) / sizeof(aac_samplerate_tab[0]); index++) {
        if (sampleRate == aac_samplerate_tab[index]) {
            return index;
        }
    }
    return -1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

static int snd_card_compr_open(struct snd_compr_stream *cstream) {
    struct snd_compr_runtime *runtime = cstream->runtime;
    rtk_runtime_stream_t *stream = NULL;

    ion_phys_addr_t dat;
    size_t len;

    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    rtk_compress_handle = ion_alloc(alsa_client, sizeof(rtk_runtime_stream_t), 1024, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);

    if (IS_ERR(rtk_compress_handle)) {
        ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
        goto fail;
    }

    if (ion_phys(alsa_client, rtk_compress_handle, &dat, &len) != 0) {
        ALSA_WARNING("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
        goto fail;
    }

    stream = ion_map_kernel(alsa_client, rtk_compress_handle);
    memset(stream, 0, len);
    stream->phy_addr = dat;

    //TRACE_CODE("stream phy %p virtual %p\n", stream->phy_addr, stream);

    if (createAudioComponent(stream)) {
        ALSA_WARNING("[%s %d] create Audio Component failed\n", __FUNCTION__, __LINE__);
        goto fail;
    }

/*  move to snd_card_compr_set_params
    if (createRingBuf(stream)) {
        ALSA_WARNING("[%s %d] create Audio Component failed\n", __FUNCTION__, __LINE__);
        goto fail;
    }
*/
    stream->status = SNDRV_PCM_TRIGGER_STOP;

    runtime->private_data = stream;

    if (rawdelay_mem == NULL) {
        //printk("%s create rawdelay_handle\n", __FUNCTION__);
        rawdelay_handle = ion_alloc(alsa_client, RAWDELAY_MEM_SIZE, 32, RTK_PHOENIX_ION_HEAP_AUDIO_MASK, AUDIO_ION_FLAG);

        if (IS_ERR(rawdelay_handle)) {
            ALSA_WARNING("[%s %d ion_alloc fail]\n", __FUNCTION__, __LINE__);
            goto fail;
        }

        if (ion_phys(alsa_client, rawdelay_handle, &phy_rawdelay, &len) != 0) {
            printk("[%s %d] alloc memory faild\n", __FUNCTION__, __LINE__);
            goto fail;
        }

        rawdelay_mem = ion_map_kernel(alsa_client, rawdelay_handle);
        memset(rawdelay_mem, 0, RAWDELAY_MEM_SIZE);

        RPC_TOAGENT_PUT_SHARE_MEMORY((void *)phy_rawdelay, ENUM_PRIVATEINFO_AUDIO_PROVIDE_RAWOUT_LATENCY);
    }

    return 0;

fail:
    if (alsa_client != NULL) {
        if (rawdelay_handle != NULL) {
            ion_unmap_kernel(alsa_client, rawdelay_handle);
            ion_free(alsa_client, rawdelay_handle);
            rawdelay_handle = NULL;
        }

        if (rtk_compress_handle != NULL) {
            //printk("%s free rtk_compress_handle\n", __FUNCTION__);
            ion_unmap_kernel(alsa_client, rtk_compress_handle);
            ion_free(alsa_client, rtk_compress_handle);
            rtk_compress_handle = NULL;
            stream = NULL;
        }
    }
    return -1;
}

static int snd_card_compr_free(struct snd_compr_stream *cstream) {
    int ret_val;
    rtk_runtime_stream_t *stream = cstream->runtime->private_data;

    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    if (rawdelay_mem) {
        RPC_TOAGENT_PUT_SHARE_MEMORY(NULL, ENUM_PRIVATEINFO_AUDIO_PROVIDE_RAWOUT_LATENCY);

        if (alsa_client != NULL && rawdelay_handle != NULL) {
            //printk("%s destory rawdelay_handle\n", __FUNCTION__);
            ion_unmap_kernel(alsa_client, rawdelay_handle);
            ion_free(alsa_client, rawdelay_handle);
            rawdelay_handle = NULL;
        }
        rawdelay_mem = NULL;
    }

    if (stream->audioDecId != 0) {
        destroyAudioComponent(stream);
    }

    destroyRingBuf(stream);

    if (alsa_client != NULL && rtk_compress_handle != NULL) {
        TRACE_CODE("%s %d free rtk_compress_handle\n", __FUNCTION__, __LINE__);
        ion_unmap_kernel(alsa_client, rtk_compress_handle);
        ion_free(alsa_client, rtk_compress_handle);
        rtk_compress_handle = NULL;
        stream = NULL;
    }
    ret_val = 0;
    return ret_val;
}

static unsigned long buf_memcpy2_ring(unsigned long base, unsigned long limit, unsigned long ptr, char* buf, unsigned long size)
{
    if (ptr + size <= limit)
    {
        memcpy((char*)ptr,buf,size);
    }
    else
    {
        int i = limit-ptr;
        memcpy((char*)ptr,(char*)buf,i);
        memcpy((char*)base,(char*)(buf+i),size-i);
    }

    ptr += size;
    if (ptr >= limit)
    {
        ptr = base + (ptr-limit);
    }
    return ptr;
}

static int writeData(rtk_runtime_stream_t *stream, void *data, int len)
{
    unsigned long base, limit, wp;
    base = (unsigned long)stream->virDecInRing;
    limit = base + ntohl(stream->decInRingHeader.size);// sizeof(stream->phyDecInbandRing);
    wp = base + (unsigned long)(ntohl(stream->decInRingHeader.writePtr) - ntohl(stream->decInRingHeader.beginAddr));

    ALSA_VitalPrint("base %x limit %x wp %x\n", (long)base, (long)limit, (long)wp);
    wp = buf_memcpy2_ring(base, limit, wp, (char *)data, (unsigned long)len);
    stream->decInRingHeader.writePtr = ntohl((int)(wp - base) + ntohl(stream->decInRingHeader.beginAddr));
    //TRACE_CODE("[INBAND RING] writeAddr %x\n", stream->decInRingHeader.writePtr);
    return len;
}

static int writeInbandCmd2(rtk_runtime_stream_t *stream, void *data, int len)
{
    unsigned long base, limit, wp;
    base = (unsigned long)stream->virInbandRing;
    limit = base + ntohl(stream->decInbandRingHeader.size);// sizeof(stream->phyDecInbandRing);
    wp = base + (unsigned long)(ntohl(stream->decInbandRingHeader.writePtr) - ntohl(stream->decInbandRingHeader.beginAddr));

    ALSA_VitalPrint("base %x limit %x wp %x\n", (long)base, (long)limit, (long)wp);
    wp = buf_memcpy2_ring(base, limit, wp, (char *)data, (unsigned long)len);
    stream->decInbandRingHeader.writePtr = ntohl((int)(wp - base) + ntohl(stream->decInbandRingHeader.beginAddr));
    //TRACE_CODE("[INBAND RING] writeAddr %x\n", stream->decInbandRingHeader.writePtr);
    return len;
}

static int snd_card_compr_set_params(struct snd_compr_stream *cstream, struct snd_compr_params *params) {

    rtk_runtime_stream_t *stream = cstream->runtime->private_data;
    AUDIO_RPC_SENDIO sendio;
    AUDIO_DEC_NEW_FORMAT cmd;
    unsigned int buffer_size;

    buffer_size = params->buffer.fragment_size * params->buffer.fragments;

    if (createRingBuf(stream, buffer_size)) {
        ALSA_WARNING("[%s %d] create Audio Component failed\n", __FUNCTION__, __LINE__);
        return -1;
    }

    TRACE_CODE("[+] %s %d\n", __FUNCTION__, __LINE__);
    TRACE_CODE("codec id   %x\n", params->codec.id);
    TRACE_CODE("codec ch   %d\n", params->codec.ch_in);
    TRACE_CODE("codec rate %d\n", params->codec.sample_rate);

    stream->audioChannel = params->codec.ch_in;
    stream->audioSamplingRate = params->codec.sample_rate;

    // decoder flush
    sendio.instanceID = stream->audioDecId;
    sendio.pinID = stream->audioDecPinId;
    if (RPC_TOAGENT_FLUSH_SVC(&sendio)) {
        ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //run audio component
    triggerAudio(stream, SNDRV_PCM_TRIGGER_START);

    //send audio format to inband cmd
    memset(&cmd, 0, sizeof(cmd));

    switch (params->codec.id) {
        case SND_AUDIOCODEC_MP3:
            TRACE_CODE("SND_AUDIO_MP3\n");
            cmd.audioType = htonl(AUDIO_MPEG_DECODER_TYPE);
            break;
        case SND_AUDIOCODEC_AAC:
            TRACE_CODE("SND_AUDIO_AAC\n");
#if 0
            cmd.audioType = htonl(AUDIO_AAC_DECODER_TYPE);
#else
            cmd.audioType = htonl(AUDIO_RAW_AAC_DECODER_TYPE);
            cmd.privateInfo[0] = htonl(params->codec.ch_in);
            cmd.privateInfo[1] = htonl(GetSampleIndex(params->codec.sample_rate));
            cmd.privateInfo[2] = htonl(OBJT_TYPE_LC);
            cmd.privateInfo[3] = htonl(0);
#endif
            break;
        case SND_AUDIOCODEC_AC3:
            printk("SND_AUDIO_AC3\n");
            cmd.audioType = htonl(AUDIO_AC3_DECODER_TYPE);
            break;
        case SND_AUDIOCODEC_EAC3:
            printk("SND_AUDIO_EAC3\n");
            cmd.audioType = htonl(AUDIO_DDP_DECODER_TYPE);
            break;
        case SND_AUDIOCODEC_DTS:
            printk("SND_AUDIO_DTS\n");
            cmd.audioType = htonl(AUDIO_DTS_DECODER_TYPE);
            break;
        case SND_AUDIOCODEC_DTS_HD:
            printk("SND_AUDIO_DTS_HD\n");
            cmd.audioType = htonl(AUDIO_DTS_HD_DECODER_TYPE);
            break;
        case SND_AUDIOCODEC_TRUEHD:
            printk("SND_AUDIO_TRUEHD\n");
            cmd.audioType = htonl(AUDIO_MLP_DECODER_TYPE);
            break;
        default:
            ALSA_WARNING("[%s %d] audio format not support\n", __FUNCTION__, __LINE__);
            break;
    }

    cmd.header.type = htonl(AUDIO_DEC_INBAMD_CMD_TYPE_NEW_FORMAT);
    cmd.header.size = htonl(sizeof(AUDIO_DEC_NEW_FORMAT));
    cmd.wPtr = htonl(stream->phyDecInRing);
#ifdef CONFIG_64BIT
    writeInbandCmd2(stream, &cmd, sizeof(AUDIO_DEC_NEW_FORMAT));
#else
    snd_realtek_hw_ring_write(&stream->decInbandRingHeader, &cmd, sizeof(AUDIO_DEC_NEW_FORMAT),
        (unsigned long)stream->virInbandRing - (unsigned long)stream->phyDecInbandRing);
#endif

#if 0 //deliver pts to inband cmd
    AUDIO_DEC_PTS_INFO ptsCmd;
    ptsCmd.header.type = AUDIO_DEC_INBAND_CMD_TYPE_PTS;
    ptsCmd.header.size = sizeof (AUDIO_DEC_PTS_INFO);
    ptsCmd.PTSH = 0 >> 32;
    ptsCmd.PTSL = 0;
    snd_realtek_hw_ring_write(&stream->decInbandRingHeader, &ptsCmd, sizeof(AUDIO_DEC_PTS_INFO),
        (unsigned long)stream->virInbandRing - (unsigned long)stream->phyDecInbandRing);
#endif
    TRACE_CODE("[-] %s %d\n", __FUNCTION__, __LINE__);
    return 0;
}

static int snd_card_compr_set_metadata(struct snd_compr_stream *cstream, struct snd_compr_metadata *metadata) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    return 0;
}
/*
static int snd_card_compr_get_params(struct snd_compr_stream *cstream, struct snd_codec *params) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    return 0;
}

static int snd_card_compr_get_metadata(struct snd_compr_stream *cstream, struct snd_compr_metadata *metadata) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);
    return 0;
}
*/
static int snd_card_compr_trigger(struct snd_compr_stream *cstream, int cmd) {
    //TRACE_CODE("%s %d cmd %d\n", __FUNCTION__, __LINE__, cmd);

    int rawDelay;
    rtk_runtime_stream_t *stream = cstream->runtime->private_data;

    switch (cmd) {
        case SNDRV_PCM_TRIGGER_START:
        case SNDRV_PCM_TRIGGER_STOP:
        case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
        case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
            if (triggerAudio(stream, cmd)) {
                ALSA_WARNING("[%s %d fail]\n", __FUNCTION__, __LINE__);
            }
            break;
        case SND_COMPR_TRIGGER_DRAIN:
        case SND_COMPR_TRIGGER_PARTIAL_DRAIN:
            {
                TRACE_CODE("TRIGGER_DRAIN/TRIGGER_PARTIAL_DRAIN\n");
#if 0
                AUDIO_DEC_EOS cmd;
                cmd.header.type = htonl(AUDIO_DEC_INBAND_CMD_TYPE_EOS);
                cmd.header.size = htonl(sizeof(AUDIO_DEC_EOS));
                cmd.EOSID = htonl(0);
                cmd.wPtr = stream->decInRingHeader.writePtr;
                snd_realtek_hw_ring_write(&stream->decInbandRingHeader, &cmd, sizeof(AUDIO_DEC_INBAND_CMD_TYPE_EOS),
                    (unsigned long)stream->virInbandRing - (unsigned long)stream->phyDecInbandRing);
#endif
            } break;
        case SND_COMPR_TRIGGER_NEXT_TRACK:
            TRACE_CODE("TRIGGER_NEXT_TRACK\n");
            break;
        case SND_COMPR_TRIGGER_GET_LATENCY:
            rawDelay = snd_monitor_raw_data_queue();
            return rawDelay;
        default:
            return -EINVAL;
    }

    return 0;
}

static int snd_card_compr_pointer(struct snd_compr_stream *cstream, struct snd_compr_tstamp *tstamp) {
    //TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    rtk_runtime_stream_t *stream = cstream->runtime->private_data;

    unsigned char* ptswp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.writePtr) - ntohl(stream->dwnstrmRingHeader.beginAddr));
    unsigned char* ptsrp = stream->virDwnRing +
        (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));
    unsigned long space = 0;
    //TRACE_CODE("dwnstrm inband wp %x rp %x\n", ptswp, ptsrp);
    unsigned long frameSize = 0;
    //unsigned long queueFrames;
    if (!stream->isGetInfo) {
        if (!checkAudioInfo(stream)) {
            stream->isGetInfo = false;
            //TRACE_CODE("dsp need more data\n");
            //return 0;
        } else {
            ptswp = stream->virDwnRing +
                (ntohl(stream->dwnstrmRingHeader.writePtr) - ntohl(stream->dwnstrmRingHeader.beginAddr));
            ptsrp = stream->virDwnRing +
                (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));
            //TRACE_CODE("dwnstrm inband wp %x rp %x\n", ptswp, ptsrp);
        }
    }

    if (ptswp != ptsrp) {
        do {
            AUDIO_INBAND_CMD_TYPE infoType;
            GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, (unsigned char*)&infoType, sizeof(AUDIO_INBAND_CMD_TYPE));

            if (infoType == AUDIO_DEC_INBAND_CMD_TYPE_PRIVATE_INFO) {
                //skip private info
                AUDIO_INBAND_PRIVATE_INFO inbandInfo;
                memset(&inbandInfo, 0, INBAND_INFO_SIZE);
                space = GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, (unsigned char*)&inbandInfo, INBAND_INFO_SIZE);
                UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_INFO_SIZE, space);
                //skip pcminfo or channel index info
                if (inbandInfo.infoType == AUDIO_INBAND_CMD_PRIVATE_PCM_FMT) {
                    ptsrp = stream->virDwnRing + (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));
                    space = stream->virDwnRingUpper - ptsrp;
                    UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_PCM_SIZE, space);
                    TRACE_CODE("skip INBAND CMD PRIVATE PCM FMT\n");
                } else if (inbandInfo.infoType == AUDIO_INBAND_CMD_PRIVATE_CH_IDX) {
                    ptsrp = stream->virDwnRing + (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));
                    space = stream->virDwnRingUpper - ptsrp;
                    UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_INDEX_SIZE, space);
                    TRACE_CODE("skip INBAND CMD PRIVATE CH IDX\n");
                } else {
                    TRACE_CODE("should not be there %d\n", __LINE__);
                    break;
                }
            } else if (infoType == AUDIO_DEC_INBAND_CMD_TYPE_PTS) {
                //get ptsinfo
                AUDIO_DEC_PTS_INFO pPTSInfo;
                memset(&pPTSInfo, 0, INBAND_PTS_INFO_SIZE);
                space = GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, (unsigned char*)&pPTSInfo, INBAND_PTS_INFO_SIZE);
                //TRACE_CODE("Get pts form ACPU PTSH %d PTSL %d\n", pPTSInfo.PTSH, pPTSInfo.PTSL);
                //            frame->nTimeStamp = (OMX_S64)(((OMX_U64)pPTSInfo.PTSH << 32) | pPTSInfo.PTSL);
                //            frame->nTimeStamp = (OMX_S64)(((float)frame->nTimeStamp / 90000.0)*1E6);

                //wPtr is used to indicate the audio frame length
                //            TRACE_CODE("get frameSize from audio fw %d ptswp %p ptsrp %p\n", pPTSInfo.wPtr, ptswp, ptsrp);
                if (pPTSInfo.wPtr != 0) {
                    frameSize += pPTSInfo.wPtr;
                    UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_PTS_INFO_SIZE, space);
                } else {
                    TRACE_CODE("should not be there %d\n", __LINE__);
                    break;
                }
            } else if (infoType == AUDIO_DEC_INBAND_CMD_TYPE_EOS) {
                AUDIO_DEC_EOS pEOSInfo;

                TRACE_CODE("RECEIVE AUDIO_DEC_INBAND_CMD_TYPE_EOS\n");
                memset(&pEOSInfo, 0, INBAND_EOS_SIZE);
                space = GetBufferFromRing(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, (unsigned char*)&pEOSInfo, INBAND_EOS_SIZE);
                UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_EOS_SIZE, space);
                if (pEOSInfo.header.size == INBAND_EOS_SIZE && pEOSInfo.EOSID == 0) {
                    printk(KERN_ALERT "get audio eos\n");
                } else if (pEOSInfo.header.size == INBAND_EOS_SIZE && pEOSInfo.EOSID == -1) {
                    TRACE_CODE("should not be there %d\n", __LINE__);
                    break;
                }
            } else {
                TRACE_CODE("should not be there %d\n", __LINE__);
                break;
            }
            ptswp = stream->virDwnRing +
                (ntohl(stream->dwnstrmRingHeader.writePtr) - ntohl(stream->dwnstrmRingHeader.beginAddr));
            ptsrp = stream->virDwnRing +
                (ntohl(stream->dwnstrmRingHeader.readPtr[0]) - ntohl(stream->dwnstrmRingHeader.beginAddr));

        } while (ptswp != ptsrp);
    } else {
        TRACE_CODE("need more data %d\n", __LINE__);
        msleep(5);
    }

    tstamp->byte_offset = stream->copied_total % (u32)cstream->runtime->buffer_size;
    tstamp->copied_total = stream->copied_total;
    //tstamp->pcm_frames = 0;
    if (frameSize) {
        //UpdateRingPtr(stream->virDwnRingUpper, stream->virDwnRingLower, ptsrp, stream, INBAND_PTS_INFO_SIZE, space);
        stream->outFrames += (frameSize >> 2);
        //TRACE_CODE("stream out frames %d\n", stream->outFrames);
        TRACE_CODE("stream out frames %ld wp %p rp %p\n", frameSize, ptswp, ptsrp);
    }
#if 1
    //for IOCTL TSTAMP to get render position in user space
    tstamp->pcm_io_frames = stream->outFrames;
    if (stream->isGetInfo)
        tstamp->sampling_rate = stream->audioSamplingRate;
#else
    if (stream->isGetInfo) {
        tstamp->sampling_rate = stream->audioSamplingRate;
        queueFrames = snd_monitor_raw_data_queue() * stream->audioSamplingRate / 1000;

        if (queueFrames > stream->outFrames) {
            printk(KERN_ALERT "queueFrames %lu outFrames %lu", queueFrames, stream->outFrames);
            tstamp->pcm_io_frames = 0;
        } else {
            if (frameSize && ((stream->outFrames - queueFrames) > stream->preOutFrames))
                tstamp->pcm_io_frames = stream->outFrames - queueFrames;
            else
                tstamp->pcm_io_frames = stream->preOutFrames;
        }
        stream->preOutFrames = tstamp->pcm_io_frames;
        //printk(KERN_ALERT "renderedFrames %u samplerate %d\n", tstamp->pcm_io_frames, stream->audioSamplingRate);
    }
#endif
    //TRACE_CODE("calc bytes offset/copied bytes as %d runtime->buffer_size %d\n", tstamp->byte_offset, cstream->runtime->buffer_size);

    return 0;
}

static int snd_card_compr_copy(struct snd_compr_stream *cstream, char __user *buf, size_t count) {
    //TRACE_CODE("%s %d buf %p size %d\n", __FUNCTION__, __LINE__, buf, count);

    rtk_runtime_stream_t *stream = cstream->runtime->private_data;

    //copy data to input ringbuffer
    long wp = (long)ntohl(stream->decInRingHeader.writePtr);
    long rp = (long)ntohl(stream->decInRingHeader.readPtr[0]);
    long lower = (long)ntohl(stream->decInRingHeader.beginAddr);
    long upper = lower + (long)ntohl(stream->decInRingHeader.size);
    long writableSize = 0;
    int bufFullCount = 0;

    //TRACE_CODE("decInring wp %x rp %x\n", wp, rp);

    writableSize = validFreeSize(lower, upper, rp, wp);
    while(count > writableSize) {
        if(bufFullCount++ > 100) {
            //printk(KERN_ALERT "writableSize %ld count %zu bufFullCount %d return\n", writableSize ,count ,bufFullCount);
            return 0;
        }
        msleep(5);
        rp = (long) ntohl(stream->decInRingHeader.readPtr[0]);
        writableSize = validFreeSize(lower, upper, rp, wp);
    }
#if 1
    writeData(stream, (char *)buf, count);
#else
    snd_realtek_hw_ring_write(&stream->decInRingHeader, (char *)buf, count,
        (unsigned long)stream->virDecInRing - (unsigned long)stream->phyDecInRing);
#endif
    stream->copied_total += count;
    //printk(KERN_ALERT "copy %zu bufFullCount %d return\n", count ,bufFullCount);
    return count;
}

#if 0
static int snd_card_compr_ack(struct snd_compr_stream *cstream, size_t bytes) {
    TRACE_CODE("%s %d bytes %d\n", __FUNCTION__, __LINE__, bytes);

    rtk_runtime_stream_t *stream = cstream->runtime->private_data;
    stream->bytes_written += bytes;
    return 0;
}
#endif

static int snd_card_compr_get_caps(struct snd_compr_stream *cstream, struct snd_compr_caps *caps) {
    TRACE_CODE("%s %d\n", __FUNCTION__, __LINE__);

    caps->num_codecs = NUM_CODEC;
    caps->direction = SND_COMPRESS_PLAYBACK;
    caps->min_fragment_size = MIN_FRAGMENT_SIZE;
    caps->max_fragment_size = MAX_FRAGMENT_SIZE;
    caps->min_fragments = MIN_FRAGMENT;
    caps->max_fragments = MAX_FRAGMENT;
    caps->codecs[0] = SND_AUDIOCODEC_MP3;
    caps->codecs[1] = SND_AUDIOCODEC_AAC;
    caps->codecs[2] = SND_AUDIOCODEC_AC3;
    caps->codecs[3] = SND_AUDIOCODEC_DTS;
    caps->codecs[4] = SND_AUDIOCODEC_DTS_HD;
    caps->codecs[5] = SND_AUDIOCODEC_EAC3;
    caps->codecs[6] = SND_AUDIOCODEC_TRUEHD;
    return 0;
}

static struct snd_compr_codec_caps caps_mp3 = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 2,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = SND_AUDIOCHANMODE_MP3_STEREO,
    .descriptor[0].formats = 0,
};

static struct snd_compr_codec_caps caps_aac = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].formats = 0, //(SND_AUDIOSTREAMFORMAT_MP2ADTS | SND_AUDIOSTREAMFORMAT_MP4ADTS),
};

static struct snd_compr_codec_caps caps_ac3 = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].min_buffer = 8192,
    .descriptor[0].formats = 0,
};

static struct snd_compr_codec_caps caps_eac3 = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].min_buffer = 8192,
    .descriptor[0].formats = 0,
};

static struct snd_compr_codec_caps caps_dts = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].min_buffer = 8192,
    .descriptor[0].formats = 0,
};

static struct snd_compr_codec_caps caps_dtsHD = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].min_buffer = 8192,
    .descriptor[0].formats = 0,
};

static struct snd_compr_codec_caps caps_trueHD = {
    .num_descriptors = 1,
    .descriptor[0].max_ch = 8,
    .descriptor[0].sample_rates[0] = 48000,
    .descriptor[0].sample_rates[1] = 44100,
    .descriptor[0].sample_rates[2] = 32000,
    .descriptor[0].sample_rates[3] = 16000,
    .descriptor[0].sample_rates[4] = 8000,
    .descriptor[0].num_sample_rates = 5,
    .descriptor[0].bit_rate[0] = 320,
    .descriptor[0].bit_rate[1] = 192,
    .descriptor[0].num_bitrates = 2,
    .descriptor[0].profiles = 0,
    .descriptor[0].modes = 0,
    .descriptor[0].min_buffer = 8192,
    .descriptor[0].formats = 0,
};

static int snd_card_compr_get_codec_caps(struct snd_compr_stream *cstream, struct snd_compr_codec_caps *codec) {
    TRACE_CODE("%s %d codec %x\n", __FUNCTION__, __LINE__, codec->codec);

    switch (codec->codec) {
        case SND_AUDIOCODEC_MP3:
            *codec = caps_mp3;
            break;
        case SND_AUDIOCODEC_AAC:
            *codec = caps_aac;
            break;
        case SND_AUDIOCODEC_AC3:
            *codec = caps_ac3;
            break;
        case SND_AUDIOCODEC_EAC3:
            *codec = caps_eac3;
            break;
        case SND_AUDIOCODEC_DTS:
            *codec = caps_dts;
            break;
        case SND_AUDIOCODEC_DTS_HD:
            *codec = caps_dtsHD;
            break;
        case SND_AUDIOCODEC_TRUEHD:
            *codec = caps_trueHD;
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

int snd_monitor_raw_data_queue(void) {
    int rawOutDelay = 0;
    if (rawdelay_mem) {
        rawOutDelay = *rawdelay_mem;
        //rawOutDelay = ENDIAN_CHANGE(rawOutDelay);
        rawOutDelay = htonl(rawOutDelay);
    }
    return rawOutDelay;
}

static struct snd_compr_ops snd_card_rtk_compr_ops = {
    .open           = snd_card_compr_open,
    .free           = snd_card_compr_free,
    .set_params     = snd_card_compr_set_params,
    .get_params     = NULL, //snd_card_compr_get_params,
    .set_metadata   = snd_card_compr_set_metadata,
    .get_metadata   = NULL, //snd_card_compr_get_metadata,
    .trigger        = snd_card_compr_trigger,
    .pointer        = snd_card_compr_pointer,
    .copy           = snd_card_compr_copy,
    .ack            = NULL, //snd_card_compr_ack,
    .get_caps       = snd_card_compr_get_caps,
    .get_codec_caps = snd_card_compr_get_codec_caps
};

int snd_card_create_compress_instance(RTK_snd_card_t *pSnd, int instance_idx) {
    struct snd_compr *compr = NULL;
    int ret = 0;
    int direction = SND_COMPRESS_PLAYBACK;

    compr = kzalloc(sizeof(*compr), GFP_KERNEL);
    if (compr == NULL) {
        snd_printk(KERN_ERR "Cannot allocate compr\n");
        return -ENOMEM;
    }

    compr->ops = kzalloc(sizeof(snd_card_rtk_compr_ops), GFP_KERNEL);
    if (compr->ops == NULL) {
        snd_printk(KERN_ERR "Cannot allocate compressed ops\n");
        ret = -ENOMEM;
        goto compr_err;
    }
    memcpy(compr->ops, &snd_card_rtk_compr_ops, sizeof(snd_card_rtk_compr_ops));

    mutex_init(&compr->lock);
    ret = snd_compress_new(pSnd->card, instance_idx, direction, compr);
    if (ret < 0) {
        pr_err("snd_card_create_compress_instance failed");
        goto compr_err;
    }

    pSnd->compr = compr;
    compr->private_data = pSnd;

    TRACE_CODE("[%s %d] snd_card_create_compress_instance success\n", __FUNCTION__, __LINE__);

    return 0;

compr_err:
    if (compr->ops != NULL)
        kfree(compr->ops);
    if (compr != NULL)
        kfree(compr);
    return ret;
}
