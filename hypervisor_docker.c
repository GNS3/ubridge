/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_bridge.h>
#include <sched.h>
#include <linux/ethtool.h>

#include "ubridge.h"
#include "hypervisor.h"
#include "hypervisor_docker.h"
#include "netlink/nl.h"

struct link_req {
  struct nlmsg nlmsg;
  struct ifinfomsg ifinfomsg;
};

#ifndef VETH_INFO_PEER
 #define VETH_INFO_PEER 1
#endif


static int netdev_set_flag(hypervisor_conn_t *conn, const char *name, int flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int ifindex, len;
	int err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE)) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not open netlink connection");
	    return (-1);
	}

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "name is too long");
	    goto out;
	}

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg || !answer) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "insufficient memory");
	    goto out;
	}

    if (!(ifindex = if_nametoindex(name))) {
       hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not find interface index");
       goto out;
    }

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	link_req->ifinfomsg.ifi_change |= IFF_UP;
	link_req->ifinfomsg.ifi_flags |= flag;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (netlink_transaction(&nlh, nlmsg, answer)) {
		hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not complete netlink transaction");
		goto out;
	}
    err = 0;

out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return (err);
}

/*
 * Turn off TCP checksum for the interface
 * it's require otherwise the OS will not use
 * the checksum from the container.
 */
static int turn_off_cx(char *ifname) {
    int sock;
    struct ifreq ifr;
    struct ethtool_value eval;
    int rc;

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
        return sock;

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_data = (char *)&eval;

    eval.cmd  = ETHTOOL_STXCSUM;
    eval.data = 0;

    rc = ioctl(sock, SIOCETHTOOL, &ifr);

    close(sock);

    return rc;
}


static int cmd_create_veth_pair(hypervisor_conn_t *conn, int argc, char *argv[])
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest1, *nest2, *nest3;
	char *if1 = argv[0];
	char *if2 = argv[1];
	int err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE)) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not open netlink connection");
	    return (-1);
	}

	if (strlen(if1) >= IFNAMSIZ || strlen(if2) >= IFNAMSIZ) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "name is too long");
	    goto out;
	}

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg || !answer) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "insufficient memory");
	    goto out;
	}

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

 	nest1 = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	nla_put_string(nlmsg, IFLA_INFO_KIND, "veth");
	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	nest3 = nla_begin_nested(nlmsg, VETH_INFO_PEER);
	nlmsg->nlmsghdr.nlmsg_len += sizeof(struct ifinfomsg);
	nla_put_string(nlmsg, IFLA_IFNAME, if2);
	nla_end_nested(nlmsg, nest3);
	nla_end_nested(nlmsg, nest2);
	nla_end_nested(nlmsg, nest1);
	nla_put_string(nlmsg, IFLA_IFNAME, if1);

	if (netlink_transaction(&nlh, nlmsg, answer)) {
		hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not complete netlink transaction");
		goto out;
	}

    if (netdev_set_flag(conn, if1, IFF_UP)) {
        fprintf(stderr, "failed to enable interface '%s'", if1);
        goto out;
    }

    if (turn_off_cx(if2)) {
        hypervisor_send_reply(conn, HSC_INFO_MSG, 0, "Warning: could not turn off checksum");
    }

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "veth pair created: %s and %s", if1, if2);
    err = 0;

out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return (err);
}

static int cmd_delete_veth(hypervisor_conn_t *conn, int argc, char *argv[])
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
    int ifindex;
	char *interface = argv[0];
	int err = -1;

	if (netlink_open(&nlh, NETLINK_ROUTE)) {
	    hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not open netlink connection");
	    return (-1);
	}

    if (!(ifindex = if_nametoindex(interface))) {
       hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not find interface index for %s", interface);
       goto out;
    }

	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg || !answer) {
	    hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "insufficient memory");
	    goto out;
	}

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_DELLINK;

	if (netlink_transaction(&nlh, nlmsg, answer)) {
		hypervisor_send_reply(conn, HSC_ERR_DELETE, 1, "could not complete netlink transaction");
		goto out;
	}

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "veth interface %s has been deleted", interface);
    err = 0;

out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return (err);
}

static int cmd_move_ns(hypervisor_conn_t *conn, int argc, char *argv[])
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL;
	struct link_req *link_req;
	int ifindex;
	int err = -1;
	char *interface = argv[0];
	pid_t pid = atoi(argv[1]);
    char *dst_interface = argv[2];

	if (netlink_open(&nlh, NETLINK_ROUTE)) {
	    hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not open netlink connection");
	    return (-1);
	}

    if (!(ifindex = if_nametoindex(interface))) {
       hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not find interface index for %s", interface);
       goto out;
    }

	if (!(nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE))) {
	   hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "insufficient memory");
	   goto out;
	}

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

    nla_put_string(nlmsg, IFLA_IFNAME, dst_interface);

	nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid);
	if (netlink_transaction(&nlh, nlmsg, nlmsg)) {
		hypervisor_send_reply(conn, HSC_ERR_CREATE, 1, "could not complete netlink transaction");
		goto out;
	}

    hypervisor_send_reply(conn, HSC_INFO_OK, 1, "%s moved to namespace %d", interface, pid);
	err = 0;

out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	return err;
}

/* Docker commands */
static hypervisor_cmd_t docker_cmd_array[] = {
   { "create_veth", 2, 2, cmd_create_veth_pair, NULL },
   { "delete_veth", 1, 1, cmd_delete_veth, NULL },
   { "move_to_ns", 3, 3, cmd_move_ns, NULL },
   { NULL, -1, -1, NULL, NULL },
};

/* Hypervisor docker initialization */
int hypervisor_docker_init(void)
{
   hypervisor_module_t *module;

   module = hypervisor_register_module("docker", NULL);
   assert(module != NULL);

   hypervisor_register_cmd_array(module, docker_cmd_array);
   return(0);
}
