/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010      Fabian Knittel <fabian.knittel@lettink.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if P2MP_SERVER

#include "multi.h"
#include "options.h"
#include "vlan.h"


#ifdef ENABLE_VLAN_TAGGING
/*
 * For vlan_accept == VLAN_ONLY_UNTAGGED_OR_PRIORITY:
 *   Only untagged frames and frames that are priority-tagged (VID == 0) are
 *   accepted.  (This means that VLAN-tagged frames are dropped.)  For frames
 *   that aren't dropped, the global vlan_pvid is returned as VID.
 *
 * For vlan_accept == VLAN_ONLY_TAGGED:
 *   If a frame is VLAN-tagged the tagging is removed and the embedded VID is
 *   returned.  Any included priority information is lost.
 *   If a frame isn't VLAN-tagged, the frame is dropped.
 *
 * For vlan_accept == VLAN_ALL:
 *   Accepts both VLAN-tagged and untagged (or priority-tagged) frames and
 *   and handles them as described above.
 *
 * @param c   The global context.
 * @param buf The ethernet frame.
 * @return    Returns -1 if the frame is dropped or the VID if it is accepted.
 */
int16_t
vlan_remove_8021q_tag(const struct context *c, struct buffer *buf)
{
    struct openvpn_ethhdr eth;
    struct openvpn_8021qhdr vlanhdr;
    uint16_t vid;
    uint16_t pcp;

    if (BLEN(buf) < (sizeof(struct openvpn_8021qhdr)))
    {
        goto drop;
    }

    vlanhdr = *(const struct openvpn_8021qhdr *) BPTR(buf);

    if (vlanhdr.tpid != htons(OPENVPN_ETH_P_8021Q))
    {
        /* Untagged frame. */

        if (c->options.vlan_accept == VLAN_ONLY_TAGGED)
        {
            /* We only accept vlan-tagged frames, so drop frames without vlan-tag
             */
            msg(D_VLAN_DEBUG, "dropping frame without vlan-tag (proto/len 0x%04x)",
                ntohs(vlanhdr.tpid));
            goto drop;
        }

        msg(D_VLAN_DEBUG, "assuming pvid for frame without vlan-tag, pvid: %u (proto/len 0x%04x)",
            c->options.vlan_pvid, ntohs(vlanhdr.tpid));
        /* We return the global PVID as the VID for the untagged frame. */
        return c->options.vlan_pvid;
    }

    /* Tagged frame. */

    vid = vlanhdr_get_vid(&vlanhdr);
    pcp = vlanhdr_get_pcp(&vlanhdr);

    if (c->options.vlan_accept == VLAN_ONLY_UNTAGGED_OR_PRIORITY)
    {
        /* We only accept untagged / prio-tagged frames.
         */

        if (vid != 0)
        {
            /* VLAN-tagged frame - which isn't acceptable here - so drop it. */
            msg(D_VLAN_DEBUG, "dropping frame with vlan-tag, vid: %u (proto/len 0x%04x)",
                vid, ntohs(vlanhdr.proto));
            goto drop;
        }

        /* Fall-through for prio-tagged frames. */
    }

    /* At this point the frame is acceptable to us.  It may be prio-tagged and/or
     * VLAN-tagged. */

    if (vid != 0)
    {
        /* VLAN-tagged frame.  Strip the tagging.  Any priority information is lost. */

        msg(D_VLAN_DEBUG, "removing vlan-tag from frame: vid: %u, wrapped proto/len: 0x%04x",
            vid, ntohs(vlanhdr.proto));
        memcpy(&eth, &vlanhdr, sizeof(eth));
        eth.proto = vlanhdr.proto;

        buf_advance(buf, SIZE_ETH_TO_8021Q_HDR);
        memcpy(BPTR(buf), &eth, sizeof(eth));

        return vid;
    }
    else
    {
        /* Prio-tagged frame.  We assume that the sender knows what it's doing and
         * don't stript the tagging. */

        /* We return the global PVID as the VID for the priority-tagged frame. */
        return c->options.vlan_pvid;
    }
drop:
    /* Drop the frame. */
    buf->len = 0;
    return -1;
}

/*
 * Adds VLAN tagging to a frame.  Assumes vlan_accept == VLAN_ONLY_TAGGED
 * or VLAN_ALL and a matching PVID.
 */
void
vlan_prepend_8021q_tag(const struct context *c, struct buffer *buf)
{
    struct openvpn_ethhdr eth;
    struct openvpn_8021qhdr *vlanhdr;

    /* Frame too small? */
    if (BLEN(buf) < (int) sizeof(struct openvpn_ethhdr))
    {
        goto drop;
    }

    eth = *(const struct openvpn_ethhdr *) BPTR(buf);
    if (eth.proto == htons(OPENVPN_ETH_P_8021Q))
    {
        /* Priority-tagged frame.  (VLAN-tagged frames couldn't have reached us
         * here.)  */

        /* Frame too small for header type? */
        if (BLEN(buf) < (int) (sizeof(struct openvpn_8021qhdr)))
        {
            goto drop;
        }

        vlanhdr = (struct openvpn_8021qhdr *) BPTR(buf);
    }
    else
    {
        /* Untagged frame. */

        /* Not enough head room for VLAN tag? */
        if (buf_reverse_capacity(buf) < SIZE_ETH_TO_8021Q_HDR)
        {
            goto drop;
        }

        vlanhdr = (struct openvpn_8021qhdr *) buf_prepend(buf, SIZE_ETH_TO_8021Q_HDR);

        /* Initialise VLAN-tag ... */
        memcpy(vlanhdr, &eth, sizeof(eth));
        vlanhdr->tpid = htons(OPENVPN_ETH_P_8021Q);
        vlanhdr->proto = eth.proto;
        vlanhdr_set_pcp(vlanhdr, 0);
        vlanhdr_set_cfi(vlanhdr, 0);
    }

    vlanhdr_set_vid(vlanhdr, c->options.vlan_pvid);

    msg(D_VLAN_DEBUG, "tagging frame: vid %u (wrapping proto/len: %04x)",
        c->options.vlan_pvid, vlanhdr->proto);
    return;
drop:
    /* Drop the frame. */
    buf->len = 0;
}

/*
 * Decides whether or not to drop an ethernet frame.  VLAN-tagged frames are
 * dropped.  All other frames are accepted.
 *
 * @param buf The ethernet frame.
 * @return    Returns true if the frame should be dropped, false otherwise.
 */
bool
vlan_filter_incoming_8021q_tag(const struct buffer *buf)
{
    const struct openvpn_8021qhdr *vlanhdr;
    uint16_t vid;

    if (BLEN(buf) < (int) sizeof(struct openvpn_8021qhdr))
    {
        return false; /* Frame too small.  */
    }
    vlanhdr = (const struct openvpn_8021qhdr *) BPTR(buf);

    if (ntohs(vlanhdr->tpid) != OPENVPN_ETH_P_8021Q)
    {
        return false; /* Frame is untagged.  */
    }
    vid = vlanhdr_get_vid(vlanhdr);
    if (vid == 0)
    {
        return false; /* Frame only priority-tagged.  */
    }
    msg(D_VLAN_DEBUG, "dropping VLAN-tagged incoming frame, vid: %u", vid);
    return true;
}

void
vlan_process_outgoing_tun(struct multi_context *m, struct multi_instance *mi)
{
    if (m->top.options.vlan_accept == VLAN_ONLY_UNTAGGED_OR_PRIORITY)
    {
        /* Packets aren't VLAN-tagged on the tap device.  */

        if (m->top.options.vlan_pvid != mi->context.options.vlan_pvid)
        {
            /* Packet is coming from the wrong VID, drop it.  */
            mi->context.c2.to_tun.len = 0;
        }
    }
    else if (m->top.options.vlan_accept == VLAN_ALL)
    {
        /* Packets either need to be VLAN-tagged or not, depending on the
         * packet's originating VID and the port's native VID (PVID).  */

        if (m->top.options.vlan_pvid != mi->context.options.vlan_pvid)
        {
            /* Packets need to be VLAN-tagged, because the packet's VID does not
             * match the port's PVID.  */
            vlan_prepend_8021q_tag(&mi->context, &mi->context.c2.to_tun);
        }
    }
    else if (m->top.options.vlan_accept == VLAN_ONLY_TAGGED)
    {
        /* All packets on the port (the tap device) need to be VLAN-tagged.  */
        vlan_prepend_8021q_tag(&mi->context, &mi->context.c2.to_tun);
    }
}

#else /* ENABLE_VLAN_TAGGING */

int16_t
vlan_remove_8021q_tag(const struct context *c, struct buffer *buf)
{
    return 0;
}

void
vlan_prepend_8021q_tag(const struct context *c, struct buffer *buf)
{
}

bool
vlan_filter_incoming_8021q_tag(const struct buffer *buf)
{
    return true;
}

void
vlan_process_outgoing_tun(struct multi_context *m, struct multi_instance *mi)
{
}

#endif /* ENABLE_VLAN_TAGGING */

#endif /* P2MP_SERVER */
