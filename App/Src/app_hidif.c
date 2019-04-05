/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#include <string.h>
#include "app_hidif.h"
#include "app_def.h"
#include "app_status.h"
#include "app_device.h"
#include "app_pinif.h"
#include "hwl_hid.h"
#include "hwl_rng.h"
#include "cnm_worker.h"
#include "cnm_buffer.h"
#include "fidodef.h"

/* ****************************************************************************************************************** */

#define HIDIF_CONT_TIMEOUT_MS       100
#define HIDIF_USER_WAIT_MS          30000

#define HIDIF_INIT_DATA_SIZE        (HID_PACKET_SIZE - 7)   // channel id + command + length
#define HIDIF_CONT_DATA_SIZE        (HID_PACKET_SIZE - 5)   // channel id + sequence
#define HIDIF_BUFFER_SIZE           (HIDIF_INIT_DATA_SIZE + 128 * HIDIF_CONT_DATA_SIZE)     // 7609

#define IS_INIT_PACKET(c)           (((c) & 0x80) == 0x80)
#define IS_CONT_PACKET(c)           (((c) & 0x80) == 0)
#define GET_CMD(c)                  ((c) & 0x7F)
#define SET_CMD(c)                  ((c) | 0x80)
#define GET_LEN(h, l)               (((h) << 8) | (l))
#define SET_LENH(h)                 (((h) >> 8) & 0xFF)
#define SET_LENL(l)                 ((l) & 0xFF)

#pragma pack(push, 1)

struct HidifInitPacket
{
    uint8_t     cmd_;
    uint8_t     bcnth_;
    uint8_t     bcntl_;
    uint8_t     data_[HIDIF_INIT_DATA_SIZE];
};
typedef struct HidifInitPacket      HidifInitPacket;

struct HidifContPacket
{
    uint8_t     seq_no_;
    uint8_t     data_[HIDIF_CONT_DATA_SIZE];
};
typedef struct HidifContPacket      HidifContPacket;

union HidifPacket
{
    struct
    {
        uint32_t    cid_;
        union
        {
            HidifInitPacket init_;
            HidifContPacket cont_;
        };
    }
    packet_;
    uint8_t stream_[HID_PACKET_SIZE];
};
typedef union HidifPacket           HidifPacket;

#pragma pack(pop)

struct HidifChannel
{
    uint32_t    cid_;
    uint32_t    lock_ms_;
    uint32_t    tout_ms_;
    uint8_t     rxcmd_;
    uint8_t     rxseq_;
    uint16_t    rxlen_;
    uint16_t    rxpos_;

    uint8_t     buffer_[HIDIF_BUFFER_SIZE];
};
typedef struct HidifChannel         HidifChannel;

struct HidifData
{
    HidifChannel    channel_;
};
typedef struct HidifData    HidifData;

/* ****************************************************************************************************************** */

static HidifData   _hidif_data;

/* ****************************************************************************************************************** */

static void process_msg(HidifChannel *channel, uint32_t now_ms)
{
//    bool    keepalive = u2f_request(channel->buffer_, channel->rxlen_);
//
//    if (ba_hidif.size() > 0)
//        hidif_write(HIDIF_MSG, ba_hidif.head(), ba_hidif.size());
//
//    return keepalive;
}

static void process_cbor(HidifChannel *channel, uint32_t now_ms)
{
}

static void process_pin(HidifChannel *channel, uint32_t now_ms)
{
    pinif_postman(channel->cid_, channel->buffer_, channel->rxlen_, now_ms);
}

static void process_cipher(HidifChannel *channel, uint32_t now_ms)
{
}

static void process_ping(HidifChannel *channel, uint32_t now_ms)
{
    ba_hidif.add_bytes(channel->buffer_, channel->rxlen_);
    hidif_write(channel->cid_, HIDIF_PING, ba_hidif.head(), ba_hidif.size());
}

static void process_lock(HidifChannel *channel, uint32_t now_ms)
{
    channel->lock_ms_ = now_ms + channel->buffer_[0] * 1000;
    hidif_write(channel->cid_, HIDIF_LOCK, NULL, 0);
}

static void process_init(HidifChannel *channel, uint32_t now_ms)
{
    uint32_t    cid = channel->cid_;
    DeviceInfo  *device_info = device_get_info();

    if (cid == HIDIF_BROADCAST_CID)
        rng_words(&cid, 1);

    ba_hidif.add_bytes(channel->buffer_, 8);
    ba_hidif.add_bytes((uint8_t*)&cid, 4);
    ba_hidif.add_byte(HIDIF_PROTOCOL_VERSION);
    ba_hidif.add_byte(device_info->ver_.major_);
    ba_hidif.add_byte(device_info->ver_.minor_);
    ba_hidif.add_byte(device_info->ver_.build_ & 0xFF);
    ba_hidif.add_byte(FIDO_CAPABILITIES);

    hidif_write(channel->cid_, HIDIF_INIT, ba_hidif.head(), ba_hidif.size());

    if (cid == HIDIF_BROADCAST_CID)
        channel->cid_ = cid;
}

static void process_wink(HidifChannel *channel, uint32_t now_ms)
{
    status_postman(_AppStatus_Busy_);
    hidif_write(channel->cid_, HIDIF_WINK, NULL, 0);
}

static void process_cancel(HidifChannel *channel, uint32_t now_ms)
{
    status_postman(_AppStatus_Idle_);

    pinif_reset();
    // u2fif_reset();
    // authnif_reset();
    // cipherif_reset();

    channel->lock_ms_ = 0;
}

static void message_process(HidifChannel *channel, uint32_t now_ms)
{
    switch (channel->rxcmd_)
    {
    case HIDIF_MSG:
        process_msg(channel, now_ms);
        break;
    case HIDIF_CBOR:
        process_cbor(channel, now_ms);
        break;
    case HIDIF_PIN:
        process_pin(channel, now_ms);
        break;
    case HIDIF_CIPHER:
        process_cipher(channel, now_ms);
        break;
    case HIDIF_PING:
        process_ping(channel, now_ms);
        break;
    case HIDIF_LOCK:
        process_lock(channel, now_ms);
        break;
    case HIDIF_INIT:
        process_init(channel, now_ms);
        break;
    case HIDIF_WINK:
        process_wink(channel, now_ms);
        break;
    case HIDIF_CANCEL:
        process_cancel(channel, now_ms);
        break;
    default:
        hidif_send_error(channel->cid_, FIDO_ERR_INVALID_COMMAND);
        break;
    }
}

static bool process_timeout(HidifChannel *channel, uint32_t now_ms)
{
    if (channel->tout_ms_ > now_ms)
    {
        channel->tout_ms_ = 0;
        channel->rxseq_ = 0;
        channel->rxlen_ = 0;
        channel->rxpos_ = 0;

        return true;
    }

    return false;
}

static bool wakeup_func(uint32_t now_ms, uint32_t wakeup_ms, uint32_t worker_ms, void *param)
{
    process_timeout(&((HidifData*)param)->channel_, now_ms);

    return hid_check_empty() ? false : true;
}

static void worker_func(uint32_t now_ms, uint32_t worker_ms, void *param)
{
    HidifData       *this = (HidifData*)param;
    HidifChannel    *channel = &this->channel_;
    HidifPacket     packet;
    bool            message_ready = false;

    while (hid_recv(packet.stream_, sizeof(HidifPacket)) > 0)
    {
        if (packet.packet_.cid_ == HIDIF_INVALID_CID)
            break;

        if (channel->cid_ != packet.packet_.cid_)
        {
            if (channel->lock_ms_ > now_ms)
            {
                hidif_send_error(packet.packet_.cid_, FIDO_ERR_OTHER);
                break;
            }

            channel->cid_ = packet.packet_.cid_;
            channel->lock_ms_ = 0;
            channel->tout_ms_ = 0;
            channel->rxpos_ = 0;
            channel->rxlen_ = 0;
        }

        if (channel->rxpos_ == 0)
        {
            /* INIT packet */

            if (IS_INIT_PACKET(packet.packet_.init_.cmd_))
            {
                HidifInitPacket *init_packet = &packet.packet_.init_;
                uint16_t        len = GET_LEN(init_packet->bcnth_, init_packet->bcntl_);

                channel->rxcmd_ = GET_CMD(init_packet->cmd_);
                channel->rxseq_ = 0;
                channel->rxlen_ = len;

                if (len > HIDIF_INIT_DATA_SIZE)
                    len = HIDIF_INIT_DATA_SIZE;
                memcpy(channel->buffer_, init_packet->data_, HIDIF_INIT_DATA_SIZE);
                channel->rxpos_ = len;

                if (channel->rxpos_ >= channel->rxlen_)
                {
                    message_ready = true;
                    break;
                }

                channel->tout_ms_ = now_ms + HIDIF_CONT_TIMEOUT_MS;
            }
            else
            {
                hidif_send_error(channel->cid_, FIDO_ERR_INVALID_PARAMETER);
                break;
            }
        }
        else
        {
            /* CONT packet */

            if (IS_CONT_PACKET(packet.packet_.cont_.seq_no_))
            {
                HidifContPacket *cont_packet = &packet.packet_.cont_;

                if (cont_packet->seq_no_ != channel->rxseq_)
                {
                    hidif_send_error(channel->cid_, FIDO_ERR_INVALID_SEQ);
                    break;
                }

                uint16_t    len = channel->rxpos_ + HIDIF_CONT_DATA_SIZE;

                if (len > channel->rxlen_)
                    len = channel->rxlen_;
                memcpy(channel->buffer_ + channel->rxpos_, cont_packet->data_, HIDIF_CONT_DATA_SIZE);
                channel->rxpos_ = len;

                if (channel->rxpos_ >= channel->rxlen_)
                {
                    message_ready = true;
                    break;
                }

                channel->rxseq_++;
                channel->tout_ms_ = now_ms + HIDIF_CONT_TIMEOUT_MS;
            }
            else
            {
                hidif_send_error(channel->cid_, FIDO_ERR_INVALID_PARAMETER);
                break;
            }
        }
    }

    if (message_ready)
    {
        message_process(channel, now_ms);

        channel->tout_ms_ = 0;
        channel->rxseq_ = 0;
        channel->rxlen_ = 0;
        channel->rxpos_ = 0;
    }
}

void hidif_init(void)
{
    worker_join(wakeup_func, worker_func, _WorkerPrio_UserHigh_, &_hidif_data);
}

void hidif_write(uint32_t cid, uint8_t cmd, uint8_t *dat, uint16_t len)
{
    if ((cid != HIDIF_INVALID_CID) && (cid == _hidif_data.channel_.cid_))
    {
        HidifPacket     packet;
        HidifInitPacket *init_packet = &packet.packet_.init_;
        uint16_t        pos = 0;

        packet.packet_.cid_ = cid;
        init_packet->cmd_   = SET_CMD(cmd);
        init_packet->bcnth_ = SET_LENH(len);
        init_packet->bcntl_ = SET_LENL(len);

        for (int8_t i = 0; i < HIDIF_INIT_DATA_SIZE; i++)
        {
            if (pos < len)
                init_packet->data_[i] = dat[pos];
            else
                init_packet->data_[i] = 0;
            pos++;
        }

        hid_send(packet.stream_, HID_PACKET_SIZE);

        if (pos < len)
        {
            HidifContPacket *cont_packet = &packet.packet_.cont_;

            cont_packet->seq_no_ = 0;

            while (pos < len)
            {
                for (int8_t i = 0; i < HIDIF_CONT_DATA_SIZE; i++)
                {
                    if (pos < len)
                        cont_packet->data_[i] = dat[pos];
                    else
                        cont_packet->data_[i] = 0;
                    pos++;
                }

                hid_send(packet.stream_, HID_PACKET_SIZE);
                cont_packet->seq_no_++;
            }
        }
    }
}

void hidif_send_error(uint32_t cid, uint8_t code)
{
    hidif_write(cid, HIDIF_ERROR, &code, 1);
}

/* end of file ****************************************************************************************************** */
