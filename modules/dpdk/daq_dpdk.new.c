#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#include "daq_module_api.h"

#define DAQ_DPDK_VERSION 21.11

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_ARGS 64

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
#define DPDKINST_STARTED	0x1
    uint32_t flags;
    int rx_rings;
    int tx_rings;
    int port;
    int index;
    int tx_start;
    int tx_end;
    struct rte_mempool *mbuf_pool;
    struct rte_mbuf *tx_burst[BURST_SIZE * RX_RING_NUM];
} DpdkInstance;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    DpdkInstance *instances;
    int intf_count;
    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} Dpdk_Context_t;
///

static int dpdk_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}
static int dpdk_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int dpdk_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr){
    
    Dpdk_Context_t *dpdkc;
    DpdkInstance *instance;

    // to check 
    Dpdk_Context_t *dpdkc;
    DpdkInstance *instance;
    DAQ_Dict *entry;
    char intf[IFNAMSIZ];
    int num_intfs = 0;
    int port1, port2, ports;
    size_t len;
    char *dev;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char argv0[] = "fake";
    char *argv[MAX_ARGS + 1];
    int argc;
    //

    dpdkc = calloc(1, sizeof(Dpdk_Context_t));

    if (!dpdkc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    dpdkc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (!dpdkc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    dpdkc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    dpdkc->timeout = (int) daq_base_api.config_get_timeout(modcfg);
    dpdkc->promisc_flag = true; // you should always set the interface //TODO

    /* Import the DPDK arguments */
    for (entry = modcfg->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "dpdk_args"))
            dpdk_args = entry->value;
    }
    if (!dpdk_args)
    {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }
    argv[0] = argv0;
    argc = parse_args(dpdk_args, &argv[1]) + 1;
    optind = 1;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n",
                __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }
    ports = rte_eth_dev_count_total();
    if (ports == 0)
    {
        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }

    dev = dpdkc->device;
    if (*dev == ':' || ((len = strlen(dev)) > 0 && *(dev + len - 1) == ':') ||
            (daq_base_api.config_get_mode(modcfg) == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        SET_ERROR(modinst, "%s: Invalid interface specification: '%s'!", __func__, afpc->device);
        goto err;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!dpdkc->instances || (daq_base_api.config_get_mode(modcfg) != DAQ_MODE_PASSIVE && num_intfs != 0))
    {
        SET_ERROR(modinst, "%s: Invalid interface specification: '%s'!", __func__, dpdkc->device);
        goto err;
    }    
    // Maybe we need to create the rings here
    dpdkc->curr_instance = dpdkc->instances;

    *ctxt_ptr = dpdkc;

    return DAQ_SUCCESS;
err:
    if (dpdkc)
    {
        dpdk_close(dpdkc);
        if (dpdkc->device)
            free(dpdkc->device);
        free(dpdkc);
    }
    return rval;
}

static void dpdk_destroy_instance(DpdkInstance *instance)
{
    if (instance)
    {
        if (instance->flags & DPDKINST_STARTED)
        {
            for (int i = instance->tx_start; i < instance->tx_end; i++)
                rte_pktmbuf_free(instance->tx_burst[i]);

            rte_eth_dev_stop(instance->port);
            instance->flags &= ~DPDKINST_STARTED;
        }

        free(instance);
    }
}
static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    struct sfbpf_program fcode;

    if (dpdkc->filter)
        free(dpdkc->filter);

    dpdkc->filter = strdup(filter);
    if (!dpdkc->filter)
    {
        SET_ERROR(dpdkc->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    /* not sure what it does
    if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->filter, 1, 0) < 0)
    {
        SET_ERROR(dpdkc->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }*/

    sfbpf_freecode(&dpdkc->fcode);
    dpdkc->fcode.bf_len = fcode.bf_len;
    dpdkc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t afpacket_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ dpdk_daq_module_load,
    /* .unload = */ dpdk_daq_module_unload,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */ dpdk_daq_instantiate,
    /* .destroy = */ dpdk_daq_destroy,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ ,
    /* .inject = */ ,
    /* .inject_relative = */ ,
    /* .interrupt = */ ,
    /* .stop = */ ,
    /* .ioctl = */ ,
    /* .get_stats = */ ,
    /* .reset_stats = */ ,
    /* .get_snaplen = */ ,
    /* .get_capabilities = */ ,
    /* .get_datalink_type = */ ,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ ,
    /* .msg_finalize = */ ,
    /* .get_msg_pool_info = */ ,
};
