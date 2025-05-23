/* tap-icmpstat.c
 * icmpstat   2011 Christopher Maynard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides icmp echo request/reply SRT statistics to tshark.
 * It is only used by tshark and not wireshark
 *
 * It was based on tap-rpcstat.c and doc/README.tapping.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/dissectors/packet-icmp.h>

#include <wsutil/cmdarg_err.h>

void register_tap_listener_icmpstat(void);

/* used to keep track of the ICMP statistics */
typedef struct _icmpstat_t {
    char *filter;
    GSList *rt_list;
    unsigned num_rqsts;
    unsigned num_resps;
    unsigned min_frame;
    unsigned max_frame;
    double min_msecs;
    double max_msecs;
    double tot_msecs;
} icmpstat_t;


/* This callback is never used by tshark but it is here for completeness.  When
 * registering below, we could just have left this function as NULL.
 * (But this may soon change; see #20432.)
 *
 * When used by wireshark, this function will be called whenever we would need
 * to reset all state, such as when wireshark opens a new file, when it starts
 * a new capture, when it rescans the packetlist after some prefs have changed,
 * etc.
 *
 * So if your application has some state it needs to clean up in those
 * situations, here is a good place to put that code.
 */
static void
icmpstat_reset(void *tapdata)
{
    icmpstat_t *icmpstat = (icmpstat_t *)tapdata;

    g_slist_free_full(g_steal_pointer(&icmpstat->rt_list), g_free);
    icmpstat->num_rqsts = 0;
    icmpstat->num_resps = 0;
    icmpstat->min_frame = 0;
    icmpstat->max_frame = 0;
    icmpstat->min_msecs = 1.0 * UINT_MAX;
    icmpstat->max_msecs = 0.0;
    icmpstat->tot_msecs = 0.0;
}


/* This callback is never used by tshark but it is here for completeness.  When
 * registering below, we could just have left this function as NULL.
 * (But this may soon change; see #20432.)
 *
 * When used by wireshark, this function will be called when our listener is
 * being removed.
 *
 * So if your application has allocated any memory, this is where to free it.
 */
static void
icmpstat_finish(void *tapdata)
{
    icmpstat_t *icmpstat = (icmpstat_t *)tapdata;

    g_slist_free_full(icmpstat->rt_list, g_free);
    g_free(icmpstat->filter);
    g_free(icmpstat);
}


static int compare_doubles(const void *a, const void *b)
{
    double ad, bd;

    ad = *(const double *)a;
    bd = *(const double *)b;

    if (ad < bd)
        return -1;
    if (ad > bd)
        return 1;
    return 0;
}


/* This callback is invoked whenever the tap system has seen a packet we might
 * be interested in.  The function is to be used to only update internal state
 * information in the *tapdata structure, and if there were state changes which
 * requires the window to be redrawn, return TAP_PACKET_REDRAW and (*draw) will
 * be called sometime later.
 *
 * This function should be as lightweight as possible since it executes
 * together with the normal wireshark dissectors.  Try to push as much
 * processing as possible into (*draw) instead since that function executes
 * asynchronously and does not affect the main thread's performance.
 *
 * If it is possible, try to do all "filtering" explicitly since you will get
 * MUCH better performance than applying a similar display-filter in the
 * register call.
 *
 * The third parameter is tap dependent.  Since we register this one to the
 * "icmp" tap, the third parameter type is icmp_transaction_t.
 *
 * function returns :
 *  TAP_PACKET_DONT_REDRAW: no updates, no need to call (*draw) later
 *  TAP_PACKET_REDRAW: state has changed, call (*draw) sometime later
 */
static tap_packet_status
icmpstat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    icmpstat_t *icmpstat = (icmpstat_t *)tapdata;
    const icmp_transaction_t *trans = (const icmp_transaction_t *)data;
    double resp_time, *rt;

    if (trans == NULL)
        return TAP_PACKET_DONT_REDRAW;

    if (trans->resp_frame) {
        resp_time = nstime_to_msec(&trans->resp_time);
        rt = g_new(double, 1);
        if (rt == NULL)
            return TAP_PACKET_DONT_REDRAW;
        *rt = resp_time;
        icmpstat->rt_list = g_slist_prepend(icmpstat->rt_list, rt);
        icmpstat->num_resps++;
        if (icmpstat->min_msecs > resp_time) {
            icmpstat->min_frame = trans->resp_frame;
            icmpstat->min_msecs = resp_time;
        }
        if (icmpstat->max_msecs < resp_time) {
            icmpstat->max_frame = trans->resp_frame;
            icmpstat->max_msecs = resp_time;
        }
        icmpstat->tot_msecs += resp_time;
    } else if (trans->rqst_frame)
        icmpstat->num_rqsts++;
    else
        return TAP_PACKET_DONT_REDRAW;

    return TAP_PACKET_REDRAW;
}


/*
 * Compute the mean, median and standard deviation.
 */
static void compute_stats(icmpstat_t *icmpstat, double *mean, double *med, double *sdev)
{
    GSList *slist;
    double diff;
    double sq_diff_sum = 0.0;

    icmpstat->rt_list = g_slist_sort(icmpstat->rt_list, compare_doubles);
    slist = icmpstat->rt_list;

    if (icmpstat->num_resps == 0 || slist == NULL) {
        *mean = 0.0;
        *med = 0.0;
        *sdev = 0.0;
        return;
    }

    /* (arithmetic) mean */
    *mean = icmpstat->tot_msecs / icmpstat->num_resps;

    /* median: If we have an odd number of elements in our list, then the
     * median is simply the middle element, otherwise the median is computed by
     * averaging the 2 elements on either side of the mid-point. */
    if (icmpstat->num_resps & 1)
        *med = *(double *)g_slist_nth_data(slist, icmpstat->num_resps / 2);
    else {
        *med =
            (*(double *)g_slist_nth_data(slist, (icmpstat->num_resps - 1) / 2) +
            *(double *)g_slist_nth_data(slist, icmpstat->num_resps / 2)) / 2;
    }

    /* (sample) standard deviation */
    for ( ; slist; slist = g_slist_next(slist)) {
        diff = *(double *)slist->data - *mean;
        sq_diff_sum += diff * diff;
    }
    if (icmpstat->num_resps > 1)
        *sdev = sqrt(sq_diff_sum / (icmpstat->num_resps - 1));
    else
        *sdev = 0.0;
}


/* This callback is used when tshark wants us to draw/update our data to the
 * output device.  Since this is tshark, the only output is stdout.
 * TShark will only call this callback once, which is when tshark has finished
 * reading all packets and exits.
 * (But this may soon change; see #20432.)
 * If used with wireshark this may be called any time, perhaps once every 3
 * seconds or so.
 * This function may even be called in parallel with (*reset) or (*draw), so
 * make sure there are no races.  The data in the icmpstat_t can thus change
 * beneath us.  Beware!
 *
 * How best to display the data?  For now, following other tap statistics
 * output, but here are a few other alternatives we might choose from:
 *
 * -> Windows ping output:
 *      Ping statistics for <IP>:
 *          Packets: Sent = <S>, Received = <R>, Lost = <L> (<LP>% loss),
 *      Approximate round trip times in milli-seconds:
 *          Minimum = <m>ms, Maximum = <M>ms, Average = <A>ms
 *
 * -> Cygwin ping output:
 *      ----<HOST> PING Statistics----
 *      <S> packets transmitted, <R> packets received, <LP>% packet loss
 *      round-trip (ms)  min/avg/max/med = <m>/<M>/<A>/<D>
 *
 * -> Linux ping output:
 *      --- <HOST> ping statistics ---
 *      <S> packets transmitted, <R> received, <LP>% packet loss, time <T>ms
 *      rtt min/avg/max/mdev = <m>/<A>/<M>/<D> ms
 */
static void
icmpstat_draw(void *tapdata)
{
    icmpstat_t *icmpstat = (icmpstat_t *)tapdata;
    unsigned int lost;
    double mean, sdev, med;

    printf("\n");
    printf("==========================================================================\n");
    printf("ICMP Service Response Time (SRT) Statistics (all times in ms):\n");
    printf("Filter: %s\n", icmpstat->filter ? icmpstat->filter : "<none>");
    printf("\nRequests  Replies   Lost      %% Loss\n");

    if (icmpstat->num_rqsts) {
        lost =  icmpstat->num_rqsts - icmpstat->num_resps;
        compute_stats(icmpstat, &mean, &med, &sdev);

        printf("%-10u%-10u%-10u%5.1f%%\n\n",
            icmpstat->num_rqsts, icmpstat->num_resps, lost,
            100.0 * lost / icmpstat->num_rqsts);
        printf("Minimum   Maximum   Mean      Median    SDeviation     Min Frame Max Frame\n");
        printf("%-10.3f%-10.3f%-10.3f%-10.3f%-10.3f     %-10u%-10u\n",
            icmpstat->min_msecs >= UINT_MAX ? 0.0 : icmpstat->min_msecs,
            icmpstat->max_msecs, mean, med, sdev,
            icmpstat->min_frame, icmpstat->max_frame);
    } else {
        printf("0         0         0           0.0%%\n\n");
        printf("Minimum   Maximum   Mean      Median    SDeviation     Min Frame Max Frame\n");
        printf("0.000     0.000     0.000     0.000     0.000          0         0\n");
    }
    printf("==========================================================================\n");
}


/* When called, this function will create a new instance of icmpstat.
 *
 * This function is called from tshark when it parses the -z icmp, arguments
 * and it creates a new instance to store statistics in and registers this new
 * instance for the icmp tap.
 */
static bool
icmpstat_init(const char *opt_arg, void *userdata _U_)
{
    icmpstat_t *icmpstat;
    const char *filter = NULL;
    GString *error_string;

    if (strstr(opt_arg, "icmp,srt,"))
        filter = opt_arg + strlen("icmp,srt,");

    icmpstat = (icmpstat_t *)g_try_malloc(sizeof(icmpstat_t));
    if (icmpstat == NULL) {
        cmdarg_err("Couldn't register icmp,srt tap: Out of memory");
        return false;
    }
    memset(icmpstat, 0, sizeof(icmpstat_t));
    icmpstat->min_msecs = 1.0 * UINT_MAX;

    icmpstat->filter = g_strdup(filter);

/* It is possible to create a filter and attach it to the callbacks.  Then the
 * callbacks would only be invoked if the filter matched.
 *
 * Evaluating filters is expensive and if we can avoid it and not use them,
 * then we gain performance.
 *
 * In this case we do the filtering for protocol and version inside the
 * callback itself but use whatever filter the user provided.
 */

    error_string = register_tap_listener("icmp", icmpstat, icmpstat->filter,
        TL_REQUIRES_NOTHING, icmpstat_reset, icmpstat_packet, icmpstat_draw,
        icmpstat_finish);
    if (error_string) {
        /* error, we failed to attach to the tap. clean up */
        g_free(icmpstat->filter);
        g_free(icmpstat);

        cmdarg_err("Couldn't register icmp,srt tap: %s", error_string->str);
        g_string_free(error_string, TRUE);
        return false;
    }

    return true;
}

static stat_tap_ui icmpstat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "icmp,srt",
    icmpstat_init,
    0,
    NULL
};

void
register_tap_listener_icmpstat(void)
{
    register_stat_tap_ui(&icmpstat_ui, NULL);
}
