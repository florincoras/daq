/*
** Copyright (C) 2018 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_api.h>
#include <sfbpf_dlt.h>

#include <libmemif.h>
#include <sys/epoll.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define vl_msg_id(n,h) n,
typedef enum
{
#include <snort/snort_all_api_h.h>
} vl_snort_msg_id_t;
typedef enum
{
#include <memif/memif_all_api_h.h>
} vl_memif_msg_id_t;
#undef vl_msg_id

#undef vl_api_version
#define vl_api_version(n,v) static u32 snort_api_version = v;
#include <snort/snort.api.h>
#undef vl_api_version

#undef vl_api_version
#define vl_api_version(n,v) static u32 memif_api_version = v;
#include <memif/memif.api.h>
#undef vl_api_version

#define vl_typedefs		/* define message structures */
#include <snort/snort_all_api_h.h>
#include <memif/memif_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <snort/snort_all_api_h.h>
#include <memif/memif_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <snort/snort_all_api_h.h>
#include <memif/memif_all_api_h.h>
#undef vl_printfun

#define DAQ_MEMIF_VERSION       1
#define DAQ_MEMIF_DBG           1

#define ERR(_msg) snprintf(errbuf, errlen, "%s: %s", __func__, _msg);

#if DAQ_MEMIF_DBG > 0
#define DBG(_fmt, args...) clib_warning (_fmt, ## args)
#else
#defien DBG(_fmt, ...)
#endif

struct memif_context_;

typedef struct memif_interface_
{
    struct memif_contex_t *ctx;
    u32 sw_if_index;

    u16 index;
    memif_conn_handle_t conn;
    memif_buffer_t *bufs;
    u16 tx_buf_num;
    u16 rx_buf_num;
    u8 ip_addr[4];

    u16 rx_now;
} Memif_Interface_t;

typedef struct memif_context_
{
    char *device;
    int snaplen;
    int timeout;
    Memif_Interface_t *ifaces;
    volatile DAQ_State state;
    volatile int break_loop;
    DAQ_Stats_t stats;
    char errbuf[256];

    int epfd; /**< Memif epoll fd */
    uword *error_string_by_error_number;
    svm_queue_t *vl_input_queue;
    u32 client_index;

    u32 memif_msg_id_base;
    u32 snort_msg_id_base;
} Memif_Context_t;

static Memif_Context_t md_context;

#define MAX_MEMIF_BUFS 256
#define APP_NAME "memif_daq"
#define IFACE_NAME  "memif_daq_iface"

static int add_epoll_fd(int epfd, int fd, uint32_t events)
{
    if (fd < 0)
    {
        DBG("invalid fd %d", fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
        DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG("fd %d added to epoll", fd);
    return 0;
}

static int mod_epoll_fd(int epfd, int fd, uint32_t events)
{
    if (fd < 0)
    {
        DBG("invalid fd %d", fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
        DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG("fd %d moddified on epoll", fd);
    return 0;
}

static int del_epoll_fd(int epfd, int fd)
{
    if (fd < 0)
    {
        DBG("invalid fd %d", fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
        DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG("fd %d removed from epoll", fd);
    return 0;
}

static int control_fd_update(int fd, uint8_t events)
{
	Memif_Context_t *mc = &md_context;
	u32 evt = 0;

	/* convert memif event definitions to epoll events */
	if (events & MEMIF_FD_EVENT_DEL)
		return del_epoll_fd(mc->epfd, fd);

	if (events & MEMIF_FD_EVENT_READ)
		evt |= EPOLLIN;
	if (events & MEMIF_FD_EVENT_WRITE)
		evt |= EPOLLOUT;

	if (events & MEMIF_FD_EVENT_MOD)
		return mod_epoll_fd(mc->epfd, fd, evt);

	return add_epoll_fd(mc->epfd, fd, evt);
}

static void memif_interface_close (Memif_Interface_t *iface)
{
    if (!iface)
        return;
    /* TODO */
}

static int memif_daq_close(Memif_Context_t *mmc)
{
    if (!mmc)
        return -1;

    while (vec_len (mmc->ifaces))
    {
        memif_interface_close (&mmc->ifaces[0]);
        vec_del1(mmc->ifaces, 0);
    }

    mmc->state = DAQ_STATE_STOPPED;

    return 0;
}

int memif_daq_init_mem (void)
{
    mheap_t *h;
    u8 *heap;
    clib_mem_init (0, 256 << 20);
    heap = clib_mem_get_per_cpu_heap ();
    h = mheap_header (heap);
    h->flags |= MHEAP_FLAG_THREAD_SAFE;
    return 0;
}

#define MEMIF_INTERFACE_MODE_IP 1
#define MEMIF_IFACE_RX_QUEUES 1
#define MEMIF_IFACE_TX_QUEUES 1
#define MEMIF_IFACE_BUFFER_SIZE 2048
#define MEMIF_IFACE_RING_SIZE 2048

static void memif_daq_send_create_memif (Memif_Context_t *mmc)
{
    vl_api_memif_create_t *mp;
    mp = vl_msg_api_alloc (sizeof (*mp));
    memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (mmc->memif_msg_id_base + VL_API_MEMIF_CREATE);
    mp->client_index = mmc->client_index;
    mp->mode = MEMIF_INTERFACE_MODE_IP;
    mp->id = 0;
    mp->role = 0;
    mp->ring_size = clib_host_to_net_u32 (MEMIF_IFACE_RING_SIZE);
    mp->buffer_size = clib_host_to_net_u16 (MEMIF_IFACE_BUFFER_SIZE);
    mp->socket_id = 0;
    mp->rx_queues = MEMIF_IFACE_RX_QUEUES;
    mp->tx_queues = MEMIF_IFACE_TX_QUEUES;

    vl_msg_api_send_shmem (mmc->vl_input_queue, (u8 *) & mp);
}

static void memif_daq_send_snort_enable_disable (Memif_Context_t *mmc, u8 is_enable)
{
    vl_api_snort_enable_disable_t *mp;
    mp = vl_msg_api_alloc (sizeof (*mp));
    memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (mmc->snort_msg_id_base + VL_API_SNORT_ENABLE_DISABLE);
    mp->client_index = mmc->client_index;

    /* Only one memif interface for now */
    mp->sw_if_index = htonl (mmc->ifaces[0].sw_if_index);
    mp->is_enable = is_enable;
    vl_msg_api_send_shmem (mmc->vl_input_queue, (u8 *) & mp);
}

int on_connect(memif_conn_handle_t conn, void *private_ctx)
{
	Memif_Interface_t *iface = &md_context.ifaces[0];
    DBG ("memif connected!");
    memif_refill_queue(iface->conn, 0, -1, 0);
    return 0;
}

int on_disconnect(memif_conn_handle_t conn, void *private_ctx)
{
	Memif_Context_t *mc = &md_context;

    clib_warning("memif disconnected!");
    mc->state = DAQ_STATE_STOPPED;

    return 0;
}

int on_interrupt(memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
    u32 index = *((u32 *) private_ctx);
    Memif_Context_t *mmc = &md_context;
    Memif_Interface_t *iface;
    int err;

    iface = &mmc->ifaces[index];
    if (iface->index != index)
      {
        clib_warning ("invalid context: %ld/%u", index, iface->index);
        return 0;
      }

    err = memif_rx_burst (iface->conn, 0, iface->bufs, MAX_MEMIF_BUFS, &iface->rx_now);
    if (err != MEMIF_ERR_SUCCESS)
        clib_warning("memif_rx_burst: %s", memif_strerror(err));
    DBG ("interrupt with %u packets", iface->rx_now);

    iface->rx_buf_num += iface->rx_now;
    return 0;
}

static int memif_daq_init_memif_iface (Memif_Interface_t *iface)
{
    memif_conn_args_t args;
    int err;

    memset(&args, 0, sizeof(args));
    args.mode = 1;
    args.interface_id = 0;
    args.is_master = 0;
    args.log2_ring_size = 11;
    args.buffer_size = MEMIF_IFACE_BUFFER_SIZE;
    args.num_s2m_rings = 1;
    args.num_m2s_rings = 1;
    strncpy((char * ) args.interface_name, IFACE_NAME, strlen(IFACE_NAME));
    err = memif_create(&iface->conn, &args, on_connect, on_disconnect, on_interrupt, &iface->index);
    if (err != MEMIF_ERR_SUCCESS)
    {
        clib_warning("memif_create: %s", memif_strerror(err));
        return -1;
    }

    iface->tx_buf_num = 0;
    iface->rx_buf_num = 0;
    iface->bufs = (memif_buffer_t *) malloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS);
    iface->ip_addr[0] = 192;
    iface->ip_addr[1] = 168;
    iface->ip_addr[2] = 1;
    iface->ip_addr[3] = 2;

    return 0;
}

static void vl_api_memif_create_reply_t_handler(vl_api_memif_create_reply_t * mp)
{
    Memif_Context_t *mmc = &md_context;
    Memif_Interface_t *iface;

    if (!mp->retval)
    {
        vec_add2 (mmc->ifaces, iface, 1);
        iface->sw_if_index = ntohl(mp->sw_if_index);
        iface->index = 0;
        iface->conn = NULL;

    	clib_warning ("memif interface created %u", iface->sw_if_index);

        if (memif_daq_init_memif_iface(iface))
        {
            clib_warning("failed to init memif interface");
            return;
        }

        memif_daq_send_snort_enable_disable (mmc, 1/* enable */);
    }
    else
    {
        clib_warning("vpp failed to create memif interface");
    }
}

static void vl_api_snort_enable_disable_reply_t_handler(vl_api_snort_enable_disable_reply_t * mp)
{
    Memif_Context_t *mc = &md_context;

    if (!mp->retval)
    {
        mc->state = DAQ_STATE_INITIALIZED;
    	DBG ("vpp snort plugin initialized!");
    }
    else
    {
    	clib_warning ("failed to initialize vpp snort plugin");
    }
}

static void vl_api_snort_interface_flow_add_del_reply_t_handler(vl_api_snort_interface_add_del_reply_t * mp)
{
    if (mp->retval)
    {
    	clib_warning ("failed to add flow to vpp");
    }
}

#define foreach_memif_daq_msg                                   			\
_(MEMIF_CREATE_REPLY, memif_create_reply)                      				\

#define foreach_snort_msg													\
_(SNORT_ENABLE_DISABLE_REPLY, snort_enable_disable_reply)       			\
_(SNORT_INTERFACE_FLOW_ADD_DEL_REPLY, snort_interface_flow_add_del_reply)  	\


int md_connect_to_vpp(Memif_Context_t *mc)
{
    char *name = "snort_memif_daq";
    api_main_t *am = &api_main;

    /*
     * Connect to vpp
     */
	if (vl_client_connect_to_vlib("/vpe-api", name, 32) < 0)
		return -1;

	name = format(0, "memif_%08x%c", memif_api_version, 0);
	mc->memif_msg_id_base = vl_client_get_first_plugin_msg_id((char *) name);
	vec_reset_length(name);
	name = format(name, "snort_%08x%c", snort_api_version, 0);
	mc->snort_msg_id_base = vl_client_get_first_plugin_msg_id((char *) name);
	vec_free (name);

    /*
     * Setup msg handlers
     */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N + mc->memif_msg_id_base,	\
                           #n,                     				\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_memif_daq_msg
#undef _

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N + mc->snort_msg_id_base,	\
                           #n,                     				\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_snort_msg
#undef _

    mc->vl_input_queue = am->shmem_hdr->vl_input_queue;
    mc->client_index = am->my_client_index;

    return 0;
}

static int memif_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
	Memif_Context_t *mmc = &md_context;
	int rv = DAQ_ERROR, err;
	static int first = 1;

    mmc->device = strdup(config->name);
    if (!mmc->device)
    {
        ERR("Couldn't allocate memory for the device string!");
        rv = DAQ_ERROR_NOMEM;
        goto err;
    }
    mmc->snaplen = config->snaplen;
    mmc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;

    if (!first)
    {
        ERR ("Only one memif interface supported");
        goto err;
    }

    first = 0;
    memif_daq_init_mem ();
    if (md_connect_to_vpp(mmc))
    {
        ERR("Failed to connect to vpp!");
        goto err;
    }

    /*
     * Init lib
     */
    mmc->epfd = epoll_create (1);
    err = memif_init (control_fd_update, APP_NAME, NULL, NULL);
    if (err != MEMIF_ERR_SUCCESS)
    {
      clib_warning ("memif_init: %s", memif_strerror (err));
      return -1;
    }

    /*
     * Create iface and wait for reply
     */
    memif_daq_send_create_memif (mmc);
    while (mmc->state != DAQ_STATE_INITIALIZED)
        ;

    *ctxt_ptr = mmc;
    return DAQ_SUCCESS;

err:
    memif_daq_close(mmc);

    return rv;
}

static int memif_daq_set_filter(void *handle, const char *filter)
{
    /* TODO */
    return DAQ_SUCCESS;
}

static int memif_daq_start(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG ("daq module started");
    mc->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

typedef union
{
  u8 data[4];
  u32 data_u32;
  /* Aliases. */
  u8 as_u8[4];
  u16 as_u16[2];
  u32 as_u32;
} ip4_address_t;

typedef union {
  struct {
    u32 pad[3];
    ip4_address_t ip4;
  };
//  ip6_address_t ip6;
  u8 as_u8[16];
  u64 as_u64[2];
} __attribute__ ((packed)) ip46_address_t;

typedef struct
{
    u8 ip_version_and_header_length;
    u8 tos;
    u16 length;
    u16 fragment_id;
    u16 flags_and_fragment_offset;
#define IP4_HEADER_FLAG_MORE_FRAGMENTS (1 << 13)
#define IP4_HEADER_FLAG_DONT_FRAGMENT (1 << 14)
#define IP4_HEADER_FLAG_CONGESTION (1 << 15)
    u8 ttl;
    u8 protocol;
    u16 checksum;
	ip4_address_t src_address;
	ip4_address_t dst_address;
} ip4_header_t;

static int
ip4_header_bytes (ip4_header_t * i)
{
  return sizeof (u32) * (i->ip_version_and_header_length & 0xf);
}

static void *
ip4_next_header (ip4_header_t * i)
{
  return (void *) i + ip4_header_bytes (i);
}

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u16 length;
  u16 checksum;
} udp_header_t;

static void memif_daq_send_vpp_flow_action (Memif_Context_t *mc, memif_buffer_t *b, DAQ_Verdict verdict)
{
    vl_api_snort_interface_flow_add_del_t *mp;
    ip46_address_t src_ip, dst_ip;
    ip4_header_t *ih4;
    udp_header_t *uh = 0;
    u8 proto = 0;
    u32 sw_if_index;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (mc->snort_msg_id_base + VL_API_SNORT_INTERFACE_FLOW_ADD_DEL);
    mp->client_index = mc->client_index;

    sw_if_index = *(u32*) b->data;
    ih4 = b->data + sizeof (u32);
    if ((ih4->ip_version_and_header_length & 0xF0) == 0x40)
    {
    	src_ip.ip4.as_u32 = ih4->src_address.as_u32;
    	dst_ip.ip4.as_u32 = ih4->dst_address.as_u32;
    	proto = ih4->protocol;
    	if (proto == 6 || proto == 17)
			uh = ip4_next_header(ih4);
    	mp->is_ip4 = 1;
    }
    else
    {
    	mp->is_ip4 = 0;
    	clib_warning ("V6 NOT SUPPORTED");
    	/*v6 TODO */
    }

    clib_memcpy (mp->src, &src_ip, sizeof (src_ip));
    clib_memcpy (mp->dst, &dst_ip, sizeof (dst_ip));
	if (uh)
	{
		mp->src_port = uh->src_port;
		mp->dst_port = uh->dst_port;
	}
	mp->proto = proto;
    mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
    mp->action = verdict == DAQ_VERDICT_PASS;
    mp->is_add = 1;
    vl_msg_api_send_shmem (mc->vl_input_queue, (u8 *) & mp);
}

static int memif_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    Memif_Context_t *mmc = (Memif_Context_t *) handle;
    Memif_Interface_t *iface = &mmc->ifaces[0];
    memif_buffer_t *rx_buf;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    int err, i, c = 0, en, memif_err;
    struct timeval ts;
    u16 rx_qid = 0, tx_cnt = 0;
    memif_buffer_t tx_bufs[MAX_MEMIF_BUFS];
    struct epoll_event evt;
    u32 memif_events = 0;

    err = memif_rx_burst (iface->conn, 0, iface->bufs, MAX_MEMIF_BUFS, &iface->rx_now);
    if (err != MEMIF_ERR_SUCCESS)
        clib_warning("memif_rx_burst: %s", memif_strerror(err));
    iface->rx_buf_num += iface->rx_now;

    memset (&evt, 0, sizeof (evt));
    evt.events = EPOLLIN | EPOLLOUT;

    gettimeofday(&ts, NULL);

    while (c < cnt || cnt <= 0)
    {
        tx_cnt = 0;

        /* Has breakloop() been called? */
        if (mmc->break_loop)
        {
            mmc->break_loop = 0;
            return 0;
        }

        for (i = 0; i < iface->rx_now; i++)
        {
            verdict = DAQ_VERDICT_PASS;
            rx_buf = iface->bufs + i;
            daqhdr.ts = ts;
            daqhdr.caplen = rx_buf->len;
            daqhdr.pktlen = rx_buf->len;
            daqhdr.ingress_index = 0;
            daqhdr.egress_index = 0;
            daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
            daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
            daqhdr.flags = 0;
            daqhdr.opaque = 0;
            daqhdr.priv_ptr = NULL;
            daqhdr.address_space_id = 0;

            if (callback)
            {
                verdict = callback(user, &daqhdr, rx_buf->data + sizeof (u32));
                if (verdict >= MAX_DAQ_VERDICT)
                    verdict = DAQ_VERDICT_PASS;
                verdict = verdict_translation_table[verdict];
            }
            c++;

            if (verdict == DAQ_VERDICT_PASS)
            {
                tx_bufs[tx_cnt] = iface->bufs[i];
                tx_bufs[tx_cnt].data += sizeof (u32);
                tx_bufs[tx_cnt].len -= sizeof (u32);
                tx_cnt++;
            }

            memif_daq_send_vpp_flow_action (mmc, rx_buf, verdict);
        }

        if (tx_cnt)
        {
            err = memif_buffer_enq_tx(iface->conn, 0, tx_bufs, tx_cnt, &tx_cnt);
            if ((err != MEMIF_ERR_SUCCESS) && (err != MEMIF_ERR_NOBUF_RING))
            {
                clib_warning("memif buffer enq: %s", memif_strerror(err));
                break;
            }
            iface->tx_buf_num += tx_cnt;
            err = memif_tx_burst(iface->conn, 0, tx_bufs, iface->rx_now, &tx_cnt);
            if (err != MEMIF_ERR_SUCCESS)
                clib_warning("memif_tx_burst: %s", memif_strerror(err));
        }

        if (iface->rx_now)
        {
            iface->rx_buf_num -= iface->rx_now;
            err = memif_refill_queue(iface->conn, rx_qid, iface->rx_now, 0);
            if (err != MEMIF_ERR_SUCCESS)
                clib_warning("memif refill queue: %s", memif_strerror(err));
            iface->rx_now = 0;
        }

		en = epoll_wait(mmc->epfd, &evt, 1, mmc->timeout);
		if (en > 0)
		{
			/* this app does not use any other file descriptors than stds and memif control fds */
			if (evt.data.fd > 2)
			{
				if (evt.events & EPOLLIN)
					memif_events |= MEMIF_FD_EVENT_READ;
				if (evt.events & EPOLLOUT)
					memif_events |= MEMIF_FD_EVENT_WRITE;
				if (evt.events & EPOLLERR)
					memif_events |= MEMIF_FD_EVENT_ERROR;
				memif_err = memif_control_fd_handler(evt.data.fd, memif_events);
				if (memif_err != MEMIF_ERR_SUCCESS)
					clib_warning("memif_control_fd_handler: %s",
							memif_strerror(memif_err));
			}
			else
			{
				DBG("unexpected event at memif_epfd. fd %d", evt.data.fd);
				break;
			}
			gettimeofday(&ts, NULL);
		}
		else if (en == 0)
		{
			break;
		}
		else
		{
			DBG("epoll_wait: %s", strerror (errno));
			return -1;
		}
    }

    return 0;
}

static int memif_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len,
                            int reverse)
{
    /* TODO */
    return DAQ_SUCCESS;
}

static int memif_daq_breakloop(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    mc->break_loop = 1;
    return DAQ_SUCCESS;
}

static int memif_daq_stop(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    memif_daq_close(mc);
    return DAQ_SUCCESS;
}

static void memif_daq_shutdown(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    memif_daq_close(mc);
    if (mc->device)
        free(mc->device);
}

static DAQ_State memif_daq_check_status(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    return mc->state;
}

static int memif_daq_get_stats(void *handle, DAQ_Stats_t * stats)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    memcpy(stats, &mc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void memif_daq_reset_stats(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    memset(&mc->stats, 0, sizeof(DAQ_Stats_t));;
}

static int memif_daq_get_snaplen(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    return mc->snaplen;
}

static uint32_t memif_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
            DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
            DAQ_CAPA_DEVICE_INDEX;
}

static int memif_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *memif_daq_get_errbuf(void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    return mc->errbuf;
}

static void memif_daq_set_errbuf(void *handle, const char *string)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    if (!string)
        return;

    DPE(mc->errbuf, "%s", string);
}

static int memif_daq_get_device_index(void *handle, const char *device)
{
    return 0;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t memif_daq_module_data =
#endif
{
    /* .api_version = */DAQ_API_VERSION,
    /* .module_version = */DAQ_MEMIF_VERSION,
    /* .name = */"memif",
    /* .type = */DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */memif_daq_initialize,
    /* .set_filter = */memif_daq_set_filter,
    /* .start = */memif_daq_start,
    /* .acquire = */memif_daq_acquire,
    /* .inject = */memif_daq_inject,
    /* .breakloop = */memif_daq_breakloop,
    /* .stop = */memif_daq_stop,
    /* .shutdown = */memif_daq_shutdown,
    /* .check_status = */memif_daq_check_status,
    /* .get_stats = */memif_daq_get_stats,
    /* .reset_stats = */memif_daq_reset_stats,
    /* .get_snaplen = */memif_daq_get_snaplen,
    /* .get_capabilities = */memif_daq_get_capabilities,
    /* .get_datalink_type = */memif_daq_get_datalink_type,
    /* .get_errbuf = */memif_daq_get_errbuf,
    /* .set_errbuf = */memif_daq_set_errbuf,
    /* .get_device_index = */memif_daq_get_device_index,
    /* .modify_flow = */NULL,
    /* .hup_prep = */NULL,
    /* .hup_apply = */NULL,
    /* .hup_post = */NULL,
    /* .dp_add_dc = */NULL,
    /* .query_flow = */NULL
};
