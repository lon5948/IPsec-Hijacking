#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    struct sadb_msg msg;
    int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2); // open a PF_KEY socket
    bzero(&msg, sizeof(msg));
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_pid = getpid();
    write(s, &msg, sizeof(msg));

    // Parse the SADB_DUMP response to retrieve the authentication key
    char buffer[4096];
    while(1) {
        int msglen = read(s, &buffer, sizeof(buffer));
        struct sadb_msg *msgp = (struct sadb_msg*) &buffer;
        msglen -= sizeof(struct sadb_msg);
        struct sadb_ext* ext = (struct sadb_ext*)(msgp+1);
        while(msglen > 0){
            if(ext->sadb_ext_type == SADB_EXT_KEY_AUTH){
                struct sadb_key* sadbkey = (struct sadb_key*) ext;
                memcpy(key, (char *)sadbkey + sizeof(struct sadb_key), sadbkey->sadb_key_bits/8);
                break;
            }
            msglen -= ext->sadb_ext_len * 8;
            ext = (struct sadb_ext*)((char*)ext + ext->sadb_ext_len * 8);
        }
        if(msgp->sadb_msg_seq == 0) 
            break;
    }
    close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{   // Fill up self->pad and self->tlr.pad_len (Ref. RFC4303 Section 2.4)
    if(self->plen % 4 == 0) 
        self->tlr.pad_len = 2;
    else    
        self->tlr.pad_len = 6 - (self->plen % 4);
    self->pad = (uint8_t*)malloc(self->tlr.pad_len * sizeof(uint8_t));
    int count = 1;
    for(int i = 0; i < self->tlr.pad_len; i++){
        *(self->pad + i) = count;
        count++ ;
    }
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // Put everything needed to be authenticated into buff and add up nb
    memcpy(buff + nb, &self->hdr, sizeof(EspHeader));
    nb += sizeof(EspHeader);
    memcpy(buff + nb, self->pl, self->plen);
    nb += self->plen;
    memcpy(buff + nb, &self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;
    memcpy(buff + nb, &self->tlr, sizeof(EspTrailer));
    nb += sizeof(EspTrailer);
    
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{   // Collect information from esp_pkt.
    // Return payload of ESP
    memcpy(&self->hdr, esp_pkt, sizeof(EspHeader));
    memcpy(&self->tlr, esp_pkt + esp_len - HMAC96AUTHLEN - sizeof(EspTrailer), sizeof(EspTrailer));
    self->plen = esp_len - sizeof(EspHeader) - self->tlr.pad_len - sizeof(EspTrailer) - HMAC96AUTHLEN;
    memcpy(self->pl, esp_pkt + sizeof(EspHeader), self->plen);
    memcpy(self->pad, esp_pkt + sizeof(EspHeader) + self->plen, self->tlr.pad_len);
    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{   // Fill up ESP header and trailer (prepare to send)
    // header
    esp_hdr_rec.seq += 1;
    self->hdr.seq = htonl(esp_hdr_rec.seq);
    self->hdr.spi = esp_hdr_rec.spi;
    self->tlr.nxt = p;
    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}