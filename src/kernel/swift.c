#include <linux/module.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>

#include "swift.h"

MODULE_DESCRIPTION("Swift Transport Protocol");
MODULE_AUTHOR("Adrian Bondrescu/Cornel Mercan");
MODULE_LICENSE("GPL");

struct swift_sock {
	struct inet_sock sock;
	/* swift socket speciffic data */
	__be16 src;
	__be16 dst;
	__be16 len;
};

static struct swift_sock * sock_port_map[MAX_SWIFT_PORT];

static inline struct swift_sock * swift_sk(struct sock * sock)
{
	return (struct swift_sock *)(sock);
}

static inline struct swifthdr * swift_hdr(const struct sk_buff * skb)
{
	return (struct swifthdr *) skb_transport_header(skb);
}

static inline __be16 get_next_free_port(void)
{
	int i;
	for (i = MIN_SWIFT_PORT; i < MAX_SWIFT_PORT; i ++)
		if (sock_port_map[i] == NULL)
			return i;
	return 0;
}

static inline void swift_unhash(__be16 port)
{
	sock_port_map[port] = NULL;
}

static inline void swift_hash(__be16 port, struct swift_sock *ssh)
{
	sock_port_map[port] = ssh;
}

static inline struct swift_sock * swift_lookup(__be16 port)
{
	return sock_port_map[port];
}

static int swift_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct swift_sock * ssk = swift_sk(sk);

	if (!sk)
		return 0;

	swift_unhash(ssk->src);
	
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

	synchronize_net();

	sock_orphan(sk);
	sock->sk = NULL;

	skb_queue_purge(&sk->sk_receive_queue);

	printk(KERN_DEBUG "swift_release sock=%p\n", sk);
	sock_put(sk);

	return 0;
}

static int swift_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_swift *swift_addr;
	struct swift_sock *ssk;
	int err;
	__be16 port;

	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_swift)) {
		printk(KERN_ERR "Invalid size for sockaddr\n");
		goto out;
	}

	swift_addr = (struct sockaddr_swift *) addr;

	err = -EINVAL;
	if (swift_addr->sin_family != AF_INET) {
		printk(KERN_ERR "Invalid family for sockaddr\n");
		goto out;
	}

	port = ntohs(swift_addr->sin_port);

	err = -EINVAL;
	if (port == 0 || port >= MAX_SWIFT_PORT) {
		printk(KERN_ERR "Invalid value for sockaddr port (%u)\n", port);
		goto out;
	}
	
	err = -EADDRINUSE;
	if (swift_lookup(port) != NULL) {
		printk(KERN_ERR "Port %u already in use\n", port);
		goto out;
	}

	ssk = swift_sk(sock->sk);
	ssk->src = port;

	swift_hash(port, ssk);

	printk(KERN_DEBUG "Socket %p bound to port %u\n", ssk, port);
	
	return 0;

out:
	return -EINVAL;
}

static int swift_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	printk(KERN_DEBUG "swift_connect\n");
	return 0;
}

static int swift_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	int err;
	__be16 dport;
	__be32 daddr;
	__be16 sport;
	struct sk_buff * skb;
	struct sock * sk; 
	struct inet_sock * isk;
	struct swift_sock * ssk;
	struct swifthdr * shdr;
	int connected = 0;
	int totlen;
	struct rtable * rt = NULL;
	
	err = -EINVAL;
	if (sock == NULL) {
		printk(KERN_ERR "Sock is NULL\n");
		goto out;
	}
	sk = sock->sk;

	err = -EINVAL;
	if (sk == NULL) {
		printk(KERN_ERR "Sock->sk is NULL\n");
		goto out;
	}

	err = -ENOMEM;
	sport = get_next_free_port();
	if (sport == 0) {
		printk(KERN_ERR "No free ports\n");
		goto out;
	}

	isk = inet_sk(sk);
	ssk = swift_sk(sk);

	if (msg->msg_name) {
		struct sockaddr_swift * swift_addr = (struct sockaddr_swift *) msg->msg_name;
		
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*swift_addr) || swift_addr->sin_family != AF_INET) {
			printk(KERN_ERR "Invalid size or address family\n");
			goto out;
		}
		
		dport = ntohs(swift_addr->sin_port);
		if (dport == 0 || dport >= MAX_SWIFT_PORT) {
			printk(KERN_ERR "Invalid value for destination port(%u)\n", dport);
			goto out;
		}	

		daddr = swift_addr->sin_addr.s_addr;
		printk(KERN_DEBUG "Received from user space destination port=%u and address=%u\n", dport, daddr);
	} else {
		err = -EDESTADDRREQ;
		if (!ssk->dst || !isk->inet_daddr) {
			printk(KERN_ERR "No destination port/address\n");
			goto out;
		}
		dport = ssk->dst;
		daddr = isk->inet_daddr;

		printk(KERN_DEBUG "Got from socket destination port=%u and address=%u\n", dport, daddr);
		connected = 1;
	}

	totlen = len + sizeof(struct swifthdr) + sizeof(struct iphdr);
	skb = sock_alloc_send_skb(sk, totlen, msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb) {
		printk(KERN_ERR "sock_alloc_send_skb failed\n");
		goto out;
	}
	printk(KERN_DEBUG "Allocated %u bytes for skb (payload size=%u)\n", totlen, len);

	skb_reset_network_header(skb);
	skb_reserve(skb, sizeof(struct iphdr));
	printk(KERN_DEBUG "Reseted network header\n");
	skb_reset_transport_header(skb);
	skb_put(skb, sizeof(struct swifthdr));
	printk(KERN_DEBUG "Reseted transport header\n");

	shdr = (struct swifthdr *) skb_transport_header(skb);
	shdr->dst = ntohs(dport);
	shdr->src = ntohs(sport);
	shdr->len = ntohs(len + sizeof(struct swifthdr));

	printk(KERN_DEBUG "payload=%p\n", skb_put(skb, len));

	err = skb_copy_datagram_from_iovec(skb, sizeof(struct swifthdr), msg->msg_iov, 0, len);
	if (err) {
		printk(KERN_ERR "skb_copy_datagram_from_iovec failed\n");
		goto out_free;
	}
	printk(KERN_DEBUG "Copied %u bytes into the skb\n", len);

	if (connected)
		rt = (struct rtable *) __sk_dst_check(sk, 0);

	if (rt == NULL) {
		struct flowi fl = { .fl4_dst = daddr,
				    .proto = sk->sk_protocol,
				    .flags = inet_sk_flowi_flags(sk),
				  };
		err = ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0);
		if (err) {
			printk(KERN_ERR "Route lookup failed\n");
			goto out_free;
		}
		sk_dst_set(sk, dst_clone(&rt->dst));
	}
	
	err = ip_queue_xmit(skb);
	if (!err)
		printk(KERN_DEBUG "Sent %u bytes on wire\n", len);
	else
		printk(KERN_ERR "ip_queue_xmit failed\n");

	return err;

out_free:
	kfree(skb);

out:
	return err;
}

static int swift_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct sk_buff *skb;
	struct sockaddr_swift *swift_addr;
	struct sock * sk = sock->sk;
	int err, copied;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb) {
		printk(KERN_ERR "skb_recv_datagram\n");
		goto out;
	}

	printk(KERN_DEBUG "Received skb %p\n", skb);

	swift_addr = (struct sockaddr_swift *) skb->cb;
	msg->msg_namelen = sizeof(struct sockaddr_swift);

	copied = skb->len;
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err) {
		printk(KERN_ERR "skb_copy_datagram_iovec\n");
		goto out_free;
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (msg->msg_name)
		memcpy(msg->msg_name, swift_addr, msg->msg_namelen);
	
	err = copied;

out_free:
	skb_free_datagram(sk, skb);

out:
	return err;
}

static int swift_rcv(struct sk_buff *skb)
{
	struct swifthdr *shdr;
	struct swift_sock *ssk;
	__be16 len;
	__be16 src, dst;
	struct sockaddr_swift * swift_addr;
	int err;

	if (!pskb_may_pull(skb, sizeof(struct swifthdr))) {
		printk(KERN_ERR "Insufficient space for header\n");
		goto drop;
	}
	
	shdr = (struct swifthdr *) skb->data;
	len = ntohs(shdr->len);

	if (skb->len < len) {
		printk(KERN_ERR "Malformed packet (packet_len=%u, skb_len=%u)\n", len, skb->len);
		goto drop;
	}

	if (len < sizeof(struct swifthdr)) {
		printk(KERN_ERR "Malformed packet (packet_len=%u sizeof(swifthdr)=%u\n", len, sizeof(struct swifthdr));
		goto drop;
	}
	
	src = ntohs(shdr->src);
	dst = ntohs(shdr->dst);
	if (src == 0 || dst == 0 || src >= MAX_SWIFT_PORT || dst >= MAX_SWIFT_PORT) {
		printk(KERN_ERR "Malformed packet (src=%u, dst=%u)\n", shdr->src, shdr->dst);
		goto drop;
	}

	skb_pull(skb, sizeof(struct swifthdr));
	len -= sizeof(struct swifthdr);

	pskb_trim(skb, len);

	printk(KERN_DEBUG "Received %u bytes from from port=%u to port=%u\n", len - sizeof(struct swifthdr), src, dst);

	ssk = swift_lookup(dst); 
	if (ssk == NULL) {
		printk(KERN_ERR "Swift lookup failed for port %u\n", dst);
		goto drop;
	}

	BUILD_BUG_ON(sizeof(struct sockaddr_swift) > sizeof(skb->cb));
	
	swift_addr = (struct sockaddr_swift *) skb->cb;
	swift_addr->sin_family = AF_INET;
	swift_addr->sin_port = shdr->src;
	swift_addr->sin_addr.s_addr = ip_hdr(skb)->saddr;

	printk(KERN_DEBUG "Setting sin_port=%u, sin_addr=%u\n", ntohs(shdr->src), swift_addr->sin_addr.s_addr);

	err = ip_queue_rcv_skb((struct sock *) &ssk->sock, skb);
	if (err) {
		printk(KERN_ERR "ip_queu_rcv_skb\n");
		consume_skb(skb);
	}
	return NET_RX_SUCCESS;

drop:
	kfree(skb);
	return NET_RX_DROP;
}

static struct proto swift_prot = {
	.obj_size = sizeof(struct swift_sock),
	.owner    = THIS_MODULE,
	.name     = "SWIFT",
};

static const struct proto_ops swift_ops = {
	.family     = PF_INET,
	.owner      = THIS_MODULE,
	.release    = swift_release,
	.bind       = swift_bind,
	.connect    = swift_connect,
	.socketpair = sock_no_socketpair,
	.accept     = sock_no_accept,
	.getname    = sock_no_getname,
	.poll       = datagram_poll,
	.ioctl      = sock_no_ioctl,
	.listen     = sock_no_listen,
	.shutdown   = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg    = swift_sendmsg,
	.recvmsg    = swift_recvmsg,
	.mmap       = sock_no_mmap,
	.sendpage   = sock_no_sendpage,
};

static const struct net_protocol swift_protocol = {
	.handler   = swift_rcv,
	.no_policy = 1,
	.netns_ok  = 1,
};

static struct inet_protosw swift_protosw = {
	.type     = SOCK_DGRAM,
	.protocol = IPPROTO_SWIFT,
	.prot     = &swift_prot,
	.ops      = &swift_ops,
	.no_check = 0,
};

static int __init swift_init(void)
{
	int rc;

	rc = proto_register(&swift_prot, 1);
	if (rc) {
		printk(KERN_ERR "Error registering swift protocol\n");
		goto out;
	}

	rc = inet_add_protocol(&swift_protocol, IPPROTO_SWIFT);
	if (rc) {
		printk(KERN_ERR "Error adding swift protocol\n");
		goto out_unregister;
	}

	inet_register_protosw(&swift_protosw);
	printk(KERN_DEBUG "Swift entered\n");

	return 0;

out_unregister:
	proto_unregister(&swift_prot);

out:
	return rc;
}

static void __exit swift_exit(void)
{
	inet_unregister_protosw(&swift_protosw);

	inet_del_protocol(&swift_protocol, IPPROTO_SWIFT);

	proto_unregister(&swift_prot);

	printk(KERN_DEBUG "Swift exited\n");
}

module_init(swift_init);
module_exit(swift_exit);
