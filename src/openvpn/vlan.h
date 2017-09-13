/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifndef VLAN_H
#define VLAN_H

#if P2MP_SERVER

#include "multi.h"

/**
 * @file Header file for vlan related structures and functions.
 */

int16_t
vlan_remove_8021q_tag(const struct context *c, struct buffer *buf);

void
vlan_prepend_8021q_tag(const struct context *c, struct buffer *buf);

bool
vlan_filter_incoming_8021q_tag(const struct buffer *buf);

void
vlan_process_outgoing_tun(struct multi_context *m, struct multi_instance *mi);

#endif /* P2MP_SERVER */

#endif /* VLAN_H */
