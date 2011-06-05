#include <linux/module.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>

#include "swift.h"
#include "debug.h"

MODULE_DESCRIPTION("Swift Transport Protocol");
MODULE_AUTHOR("Adrian Bondrescu/Cornel Mercan");
MODULE_LICENSE("GPL");

struct swift_sock {
	struct inet_sock sock;
	/* swift socket speciffic data */
	uint8_t src;
	uint8_t dst;
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

static inline uint8_t get_next_free_port(void)
{
	int i;
	for (i = MIN_SWIFT_PORT; i < MAX_SWIFT_PORT; i ++)
		if (sock_port_map[i] == NULL)
			return i;
	return 0;
}

static inline void swift_unhash(uint8_t port)
{
	sock_port_map[port] = NULL;
}

static inline void swift_hash(uint8_t port, struct swift_sock *ssh)
{
	sock_port_map[port] = ssh;
}

static inline struct swift_sock * swift_lookup(uint8_t port)
{
	return sock_port_map[port];
}

static int swift_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct swift_sock * ssk = swift_sk(sk);

	if (unlikely(!sk))
		return 0;

	swift_unhash(ssk->src);
	
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

	synchronize_net();

	sock_orphan(sk);
	sock->sk = NULL;

	skb_queue_purge(&sk->sk_receive_queue);

	log_debug("swift_release sock=%p\n", sk);
	sock_put(sk);

	return 0;
}

static int swift_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_swift *swift_addr;
	struct swift_sock *ssk;
	int err;
	uint8_t port;

	if (unlikely(addr_len < sizeof(struct sockaddr_swift))) {
		log_error("Invalid size for sockaddr\n");
		err = -EINVAL;
		goto out;
	}

	swift_addr = (struct sockaddr_swift *) addr;

	if (unlikely(swift_addr->sin_family != AF_INET)) {
		log_error("Invalid family for sockaddr\n");
		err = -EINVAL;
		goto out;
	}

	port = ntohs(swift_addr->sin_port);

	if (unlikely(port == 0 || port >= MAX_SWIFT_PORT)) {
		log_error("Invalid value for sockaddr port (%u)\n", port);
		err = -EINVAL;
		goto out;
	}
	
	if (unlikely(swift_lookup(port) != NULL)) {
		log_error("Port %u already in use\n", port);
		err = -EADDRINUSE;
		goto out;
	}

	ssk = swift_sk(sock->sk);
	ssk->src = port;

	swift_hash(port, ssk);

	log_debug("Socket %p bound to port %u\n", ssk, port);
	
	return 0;

out:
	return err;
}

static int swift_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	int err;
	struct sock * sk; 
	struct inet_sock * isk;
	struct swift_sock * ssk;

	log_debug("swift_connect\n");

	if (unlikely(sock == NULL)) {
		log_error("Sock is NULL\n");
		err = -EINVAL;
		goto out;
	}
	sk = sock->sk;

	if (unlikely(sk == NULL)) {
		log_error("Sock->sk is NULL\n");
		err = -EINVAL;
		goto out;
	}

	isk = inet_sk(sk);
	ssk = swift_sk(sk);

	if (unlikely(ssk->src != 0)) {
		log_error("ssk->src is not NULL\n");
		err = -EINVAL;
		goto out;
	}
	
	if (likely(addr)) {
		struct sockaddr_swift * swift_addr = (struct sockaddr_swift *) addr;
		
		if (unlikely(addr_len < sizeof(*swift_addr) || swift_addr->sin_family != AF_INET)) {
			log_error("Invalid size or address family\n");
			err = -EINVAL;
			goto out;
		}
		ssk->dst = ntohs(swift_addr->sin_port);
		if (unlikely(ssk->dst == 0 || ssk->dst >= MAX_SWIFT_PORT)) {
			log_error("Invalid value for destination port(%u)\n", ssk->dst);
			err = -EINVAL;
			goto out;
		}	
	
		isk->inet_daddr = swift_addr->sin_addr.s_addr;
		log_debug("Received from user space destination port=%u and address=%u\n", ssk->dst, isk->inet_daddr);
	} else {
		log_error("Invalid swift_addr (NULL)\n");
		err = -EINVAL;
		goto out;
	}
	
	ssk->src = get_next_free_port();
	if (unlikely(ssk->src == 0)) {
		log_error("No free ports\n");
		err = -ENOMEM;
		goto out;
	}
	
	swift_hash(ssk->src, ssk);

	return 0;

out:
	return err;
}

static int swift_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	int err;
	uint8_t dport;
	__be32 daddr;
	uint8_t sport;
	struct sk_buff * skb;
	struct sock * sk; 
	struct inet_sock * isk;
	struct swift_sock * ssk;
	struct swifthdr * shdr;
	int connected = 0;
	int totlen;
	struct rtable * rt = NULL;
	
	if (unlikely(sock == NULL)) {
		log_error("Sock is NULL\n");
		err = -EINVAL;
		goto out;
	}
	sk = sock->sk;

	if (unlikely(sk == NULL)) {
		log_error("Sock->sk is NULL\n");
		err = -EINVAL;
		goto out;
	}

	isk = inet_sk(sk);
	ssk = swift_sk(sk);

	sport = ssk->src;
	if (sport == 0) {
		sport = get_next_free_port();
		if (unlikely(sport == 0)) {
			log_error("No free ports\n");
			err = -ENOMEM;
			goto out;
		}
	}

	if (msg->msg_name) {
		struct sockaddr_swift * swift_addr = (struct sockaddr_swift *) msg->msg_name;
		
		if (unlikely(msg->msg_namelen < sizeof(*swift_addr) || swift_addr->sin_family != AF_INET)) {
			log_error("Invalid size or address family\n");
			err = -EINVAL;
			goto out;
		}
		
		dport = ntohs(swift_addr->sin_port);
		if (unlikely(dport == 0 || dport >= MAX_SWIFT_PORT)) {
			log_error("Invalid value for destination port(%u)\n", dport);
			err = -EINVAL;
			goto out;
		}	

		daddr = swift_addr->sin_addr.s_addr;
		log_debug("Received from user space destination port=%u and address=%u\n", dport, daddr);
	} else {
		if (unlikely(!ssk->dst || !isk->inet_daddr)) {
			log_error("No destination port/address\n");
			err = -EDESTADDRREQ;
			goto out;
		}
		dport = ssk->dst;
		daddr = isk->inet_daddr;

		log_debug("Got from socket destination port=%u and address=%u\n", dport, daddr);
		connected = 1;
	}

	totlen = len + sizeof(struct swifthdr) + sizeof(struct iphdr);
	skb = sock_alloc_send_skb(sk, totlen, msg->msg_flags & MSG_DONTWAIT, &err);
	if (unlikely(!skb)) {
		log_error("sock_alloc_send_skb failed\n");
		goto out;
	}
	log_debug("Allocated %u bytes for skb (payload size=%u)\n", totlen, len);

	skb_reset_network_header(skb);
	skb_reserve(skb, sizeof(struct iphdr));
	log_debug("Reseted network header\n");
	skb_reset_transport_header(skb);
	skb_put(skb, sizeof(struct swifthdr));
	log_debug("Reseted transport header\n");

	shdr = (struct swifthdr *) skb_transport_header(skb);
	shdr->dst = ntohs(dport);
	shdr->src = ntohs(sport);
	shdr->len = ntohs(len + sizeof(struct swifthdr));

	log_debug("payload=%p\n", skb_put(skb, len));

	err = skb_copy_datagram_from_iovec(skb, sizeof(struct swifthdr), msg->msg_iov, 0, len);
	if (unlikely(err)) {
		log_error("skb_copy_datagram_from_iovec failed\n");
		goto out_free;
	}
	log_debug("Copied %u bytes into the skb\n", len);

	if (connected)
		rt = (struct rtable *) __sk_dst_check(sk, 0);

	if (rt == NULL) {
		struct flowi fl = { .fl4_dst = daddr,
				    .proto = sk->sk_protocol,
				    .flags = inet_sk_flowi_flags(sk),
				  };
		err = ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0);
		if (unlikely(err)) {
			log_error("Route lookup failed\n");
			goto out_free;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		sk_dst_set(sk, dst_clone(&rt->u.dst));
#else
		sk_dst_set(sk, dst_clone(&rt->dst));
#endif
	}
	
	err = ip_queue_xmit(skb);
	if (likely(!err))
		log_debug("Sent %u bytes on wire\n", len);
	else
		log_error("ip_queue_xmit failed\n");

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
	if (unlikely(!skb)) {
		log_error("skb_recv_datagram\n");
		goto out;
	}

	log_debug("Received skb %p\n", skb);

	swift_addr = (struct sockaddr_swift *) skb->cb;
	msg->msg_namelen = sizeof(struct sockaddr_swift);

	copied = skb->len;
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (unlikely(err)) {
		log_error("skb_copy_datagram_iovec\n");
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
	uint8_t src, dst;
	struct sockaddr_swift * swift_addr;
	int err;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct swifthdr)))) {
		log_error("Insufficient space for header\n");
		goto drop;
	}
	
	shdr = (struct swifthdr *) skb->data;
	len = ntohs(shdr->len);

	if (unlikely(skb->len < len)) {
		log_error("Malformed packet (packet_len=%u, skb_len=%u)\n", len, skb->len);
		goto drop;
	}

	if (unlikely(len < sizeof(struct swifthdr))) {
		log_error("Malformed packet (packet_len=%u sizeof(swifthdr)=%u\n", len, sizeof(struct swifthdr));
		goto drop;
	}
	
	src = ntohs(shdr->src);
	dst = ntohs(shdr->dst);
	if (unlikely(src == 0 || dst == 0 || src >= MAX_SWIFT_PORT || dst >= MAX_SWIFT_PORT)) {
		log_error("Malformed packet (src=%u, dst=%u)\n", shdr->src, shdr->dst);
		goto drop;
	}

	skb_pull(skb, sizeof(struct swifthdr));
	len -= sizeof(struct swifthdr);

	pskb_trim(skb, len);

	log_debug("Received %u bytes from from port=%u to port=%u\n", len - sizeof(struct swifthdr), src, dst);

	ssk = swift_lookup(dst); 
	if (ssk == NULL) {
		log_error("Swift lookup failed for port %u\n", dst);
		goto drop;
	}

	BUILD_BUG_ON(sizeof(struct sockaddr_swift) > sizeof(skb->cb));
	
	swift_addr = (struct sockaddr_swift *) skb->cb;
	swift_addr->sin_family = AF_INET;
	swift_addr->sin_port = shdr->src;
	swift_addr->sin_addr.s_addr = ip_hdr(skb)->saddr;

	log_debug("Setting sin_port=%u, sin_addr=%u\n", ntohs(shdr->src), swift_addr->sin_addr.s_addr);

	err = ip_queue_rcv_skb((struct sock *) &ssk->sock, skb);
	if (unlikely(err)) {
		log_error("ip_queu_rcv_skb\n");
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
	if (unlikely(rc)) {
		log_error("Error registering swift protocol\n");
		goto out;
	}

	rc = inet_add_protocol(&swift_protocol, IPPROTO_SWIFT);
	if (unlikely(rc)) {
		log_error("Error adding swift protocol\n");
		goto out_unregister;
	}

	inet_register_protosw(&swift_protosw);
	log_debug("Swift entered\n");

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

	log_debug("Swift exited\n");
}

module_init(swift_init);
module_exit(swift_exit);
