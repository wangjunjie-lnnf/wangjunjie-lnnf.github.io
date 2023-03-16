---
layout: post
title:  "kernel之tcp-ip协议"
date:   2023-03-12 22:22:07 +0000
categories: jekyll
tags: kernel tcp ip
---

# 发送

## L4

![tcp-header](/assets/images/2023-03-12/tcp-header.png)

Each TCP header contains the source and destination port number. These two values, along with the source and destination IP addresses in the IP header, uniquely identify each connection. The combination of an IP address and a port number is sometimes called an endpoint or socket in the TCP literature.

The Sequence Number field identifies the byte in the stream of data from the sending TCP to the receiving TCP that the first byte of data in the containing segment represents. If we consider the stream of bytes flowing in one direction between two applications, TCP numbers each byte with a sequence number. `This sequence number is a 32-bit unsigned number that wraps back around to 0 after reaching (232) − 1`. Because every byte exchanged is numbered, the ACK Number field contains the next sequence number that the sender of the acknowledgment expects to receive. This is therefore the sequence number of the last successfully received byte of data plus 1. This field is valid only if the ACK bit field is on, which it usually is for all but initial and closing segments.

When a new connection is being established, the SYN bit field is turned on in the first segment sent from client to server. Such segments are called SYN segments, or simply SYNs. The Sequence Number field then contains the first sequence number to be used on that direction of the connection for subsequent sequence numbers and in returning ACK numbers (recall that connections are all bidirectional). `Note that this number is not 0 or 1 but instead is another number, often randomly chosen, called the initial sequence number (ISN)`. The reason for the ISN not being 0 or 1 is a security measure. `The sequence number of the first byte of data sent on this direction of the connection is the ISN plus 1 because the SYN bit field consumes one sequence number`. `Consuming a sequence number also implies reliable delivery using retransmission`. Thus, SYNs and application bytes and FINs are reliably delivered. ACKs, which do not consume sequence numbers, are not.

TCP can be described as `a sliding window protocol with cumulative positive acknowledgments`. The ACK Number field is constructed to indicate the largest byte received in order at the receiver (plus 1).

The Header Length field gives the length of the header in `32-bit words`. This is required because the length of the Options field is variable. `With a 4-bit field, TCP is limited to a 60-byte header`. Without options, however, the size is 20 bytes.

1. `CWR`—`Congestion Window Reduced` (the sender reduced its sending rate);
2. `ECE`—`ECN Echo` (the sender received an earlier congestion notification);
3. URG—Urgent (the Urgent Pointer field is valid, `rarely used`);
4. `ACK`—`Acknowledgment` (the Acknowledgment Number field is valid always on after a connection is established);
5. PSH—Push (the receiver should pass this data to the application as soon as possible, `not reliably implemented or used`);
6. `RST`—`Reset` the connection (connection abort, usually because of an error);
7. `SYN`—`Synchronize` sequence numbers to initiate a connection;
8. `FIN`—The sender of the segment is finished sending data to its peer;

TCP’s flow control is provided by each end advertising a window size using the Window Size field. This is the number of bytes, `starting with the one specified by the ACK number`, that the receiver is willing to accept. This is a 16-bit field, limiting the window to 65,535 bytes, and thereby limiting TCP’s throughput performance.

The Urgent Pointer field is valid only if the URG bit field is set. This “pointer” is a positive offset that must be added to the Sequence Number field of the segment to yield the sequence number of the last byte of urgent data. TCP’s urgent mechanism is a way for the sender to provide specially marked data to the other end.

The most common Option field is the `Maximum Segment Size` option, called the `MSS`. Each end of a connection normally specifies this option on the first segment it sends (the ones with the SYN bit field set to establish the connection). `The MSS option specifies the maximum-size segment that the sender of the option is willing to receive in the reverse direction`.

```c
// 发送一个skb
int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)
{
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

    struct tcp_out_options opts;
    if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
        // 连接建立的选项
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
        {
            // tcp_output.c/tcp_connect_init中设置
	        // 取min(用户通过ioctl设置的值, ipv4_default_advmss)
            opts->mss = tcp_advertise_mss(sk);
            // 时间戳
            if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
                opts->options |= OPTION_TS;
                opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
                opts->tsecr = tp->rx_opt.ts_recent;
            }
            // 窗口size从16-bit增加到30-bit
            if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
                opts->ws = tp->rx_opt.rcv_wscale;
                opts->options |= OPTION_WSCALE;
            }
            // sack
            if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
                opts->options |= OPTION_SACK_ADVERTISE;
            }
            // fastopen
            struct tcp_sock *tp = tcp_sk(sk);
            struct tcp_fastopen_request *fastopen = tp->fastopen_req;
            if (fastopen && fastopen->cookie.len >= 0) {            
                opts->options |= OPTION_FAST_OPEN_COOKIE;
                opts->fastopen_cookie = &fastopen->cookie;
                tp->syn_fastopen = 1;
                tp->syn_fastopen_exp = fastopen->cookie.exp ? 1 : 0;
            }
        }
	} else {
        // 连接完成后的选项
		tcp_options_size = tcp_established_options(sk, skb, &opts, &md5);
        {
            // 时间戳选项
            if (likely(tp->rx_opt.tstamp_ok)) {
                opts->options |= OPTION_TS;
                opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
                opts->tsecr = tp->rx_opt.ts_recent;
            }

            eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
            if (eff_sacks) {
                // header剩余空间
                const unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
                // 每个sack需要8个直接标记头尾
                opts->num_sack_blocks = min_t(unsigned int, eff_sacks, (remaining - 4) / 8);
            }
        }
    }
    tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

    // 设置tcp header
    th = (struct tcphdr *)skb->data;
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tcp_sk(sk)->rcv_nxt);
    // 设置header长度和flag
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) | tcb->tcp_flags);

    if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		th->window  = htons(tcp_select_window(sk));
        // 拥堵标识
		tcp_ecn_send(sk, skb, th, tcp_header_size);
	} else {
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}

    tcp_options_write((__be32 *)(th + 1), tp, &opts);

    // 插入L3的发送队列
    ip_queue_xmit(sk, skb, ...);
}
```

## L3

![ip-header](/assets/images/2023-03-12/ip-header.png)

The normal size of the IPv4 header is 20 bytes, unless options are present (which is rare).

The first field (only 4 bits or one nibble wide) is the `Version` field. It contains the version number of the IP datagram: `4 for IPv4 and 6 for IPv6`.

The `Internet Header Length (IHL)` field is the number of 32-bit words in the IPv4 header, including any options. Because this is also a 4-bit field, the IPv4 header is limited to a maximum of fifteen 32-bit words or 60 bytes. The normal value of this field (when no options are present) is 5.

Following the header length, the original specification of IPv4 [RFC0791] specified a `Type of Service (ToS)` byte. Use of these never became widespread, so eventually this 8-bit field was split into two smaller parts and redefined by a set of RFCs ([RFC3260] [RFC3168][RFC2474] and others). The first 6 bits are now called the `Differentiated Services Field (DS Field)`, and the last 2 bits are the `Explicit Congestion Notification (ECN)` field or indicator bits. 

The pair of ECN bits in the header is used for `marking a datagram with a congestion indicator when passing through a router that has a significant amount of internally queued traffic`. Both bits are set by persistently congested ECN-aware routers when forwarding packets. The use case envisioned for this function is that when a marked packet is received at the destination, some protocol (such as TCP) will notice that the packet is marked and indicate this fact back to the sender, which would then slow down, thereby easing congestion before a router is forced to drop traffic because of overload.

ECN在路由过程中被路由器标记，告诉接收者道路拥堵，接收者把此消息传递给发送者，告诉发送者发慢点。

The `Total Length field` is the total length of the IPv4 datagram in bytes. Using this field and the `IHL` field, we know where the data portion of the datagram starts, and its length. Because this is a 16-bit field, the maximum size of an IPv4 datagram (including header) is `65,535` bytes. 

Although it is possible to send a 65,535-byte IP datagram, most link layers (such as `Ethernet`) are not able to carry one this large without fragmenting it (chopping it up) into smaller pieces. Furthermore, a host is not required to be able to receive an IPv4 datagram larger than `576` bytes.

Link-layer framing normally imposes an upper limit on the maximum size of a frame that can be transmitted. To keep the IP datagram abstraction consistent and isolated from link-layer details, IP employs fragmentation and reassembly. Whenever the IP layer receives an IP datagram to send, it determines which local interface the datagram is to be sent over next (via a forwarding table lookup;) and what MTU is required. IP compares the outgoing interface’s MTU with the datagram size and performs fragmentation if the datagram is too large. `Fragmentation in IPv4 can take place at the original sending host and at any intermediate routers along the end-to-end path`. Note that datagram fragments can themselves be fragmented. 

When an IP datagram is fragmented, it is not reassembled until it reaches its final destination. `It is possible for different fragments of the same datagram to follow different paths to their common destination`. If this happens, no single router along the path would in general be capable of reassembling the original datagram because it would see only a subset of the fragments.

When an IPv4 datagram is fragmented into multiple smaller fragments, each of which itself is an independent IP datagram, `the Total Length field reflects the length of the particular fragment`.

The `Identification field` helps indentify each datagram sent by an IPv4 host. To ensure that the fragments of one datagram are not confused with those of another, the sending host normally increments an internal counter by 1 each time a datagram is sent (from one of its IP addresses) and copies the value of the counter into the IPv4 Identification field.

The `Identification field` value (set by the original sender) is copied to each fragment and is used to group them together when they arrive. The `Fragment Offset` field gives the offset of the first byte of the fragment payload byte in the original IPv4 datagram (`in 8-byte units`). Clearly, the first fragment always has offset 0.

`Identification`字段用于标识多个分片属于同一个datagram

```c
/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/
```

3-bit的flags字段跟分片相关的是`DF`和`MF`.
`DF`字段告诉中间的路由器不要分片，如果超过了`MTU`，通过`ICMP`回复异常信息，`DF`通常用于探测`Path MTU`.

Finally, the `MF` bit field indicates whether more fragments in the datagram should be expected and `is 0 only in the final fragment`. When the fragment with MF = 0 is received, the reassembly process can ascertain the length of the original datagram, as a sum of the Fragment Offset field value (times 8) and the IPv4 Total Length field value (minus the IPv4 header length). Because each Offset field is relative to the original datagram, the reassembly process can handle fragments that arrive out of order. When a datagram is fragmented, the Total Length field in the IPv4 header of each fragment is changed to be the total size of that fragment.

Although IP fragmentation looks transparent, there is one feature mentioned earlier that makes it less than desirable: `if one fragment is lost, the entire datagram is lost`. To understand why this happens, realize that `IP itself has no error correction mechanism of its own`. Mechanisms such as timeout and retransmission are left as the responsibility of the higher layers.

The `Time-to-Live field`, or `TTL`, sets an upper limit on the number of routers through which a datagram can pass. It is initialized by the sender to some value (`64 is recommended` [RFC1122], although 128 or 255 is not uncommon) and `decremented by 1 by every router that forwards the datagram`. When this field reaches 0, the datagram is thrown away, and the sender is notified with an ICMP message. This `prevents packets from getting caught in the network forever` should an unwanted routing loop occur.

The `Protocol field` in the IPv4 header contains a number indicating the type of data found in the payload portion of the datagram. The most common values are `17 (for UDP) and 6 (for TCP)`. This provides a demultiplexing feature so that the IP protocol can be used to carry payloads of more than one protocol type. Although this field originally specified the transport-layer protocol the datagram is encap- sulating, it is now understood to identify the encapsulated protocol, which may or not be a transport protocol.

Every IP datagram contains the Source IP Address of the sender of the datagram and the Destination IP Address of where the datagram is destined. These are 32-bit values for IPv4 and 128-bit values for IPv6, and they usually identify a single interface on a computer, although multicast and broadcast addresses violate this rule.


```c
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	return __ip_queue_xmit(sk, skb, fl, inet_sk(sk)->tos);
    {
        struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
        if (!rt) {
            // 没有路由或路由失效则重新路由
            rt = ip_route_output_ports(net, fl4, sk,
                                        daddr, 
                                        inet->inet_saddr,
                                        inet->inet_dport,
                                        inet->inet_sport,
                                        sk->sk_protocol,
                                        RT_CONN_FLAGS_TOS(sk, tos),
                                        sk->sk_bound_dev_if);
            {
                // 根据目标地址最长匹配: `netstat -nr`查看路由表
                // Destination        Gateway            Flags           Netif 			Expire
                // default            10.0.64.1          UGScg             en0       
                // 192.168.1.0/24	  192.168.1.1		 UCS			   lo0	
                fib_lookup(net, fl4, res, 0);
                return __mkroute_output(res, fl4, orig_oif, dev_out, flags);
                {
                    rth = rt_dst_alloc(dev_out, flags, type, ...);
                    {
                        rth = dst_alloc(&ipv4_dst_ops, dev, 1, ...);
                        // 发送
                        rth->dst.output = ip_output;
                        if (flags & RTCF_LOCAL)
                            // 本地处理
                            rth->dst.input = ip_local_deliver;
                    }
                }
            }
        }

        // 开始插入ip报问头
        skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
        struct iphdr *iph = ip_hdr(skb);
        // 4标识版本号ipv4，5标识header默认长度20，tos标识优先级
        *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));
        if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
            // 通知中间的路由器不要分片，如果超过了MTU，通过ICMP回复错误信息
            iph->frag_off = htons(IP_DF);
        else
            iph->frag_off = 0;
        iph->ttl      = ip_select_ttl(inet, &rt->dst);
        iph->protocol = sk->sk_protocol;
        ip_copy_addrs(iph, fl4);

        // ip选项，通常是空的
        if (inet_opt && inet_opt->opt.optlen) {
            iph->ihl += inet_opt->opt.optlen >> 2;
            ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
        }

        ip_local_out(net, sk, skb);
        {
            // 先通过netfilter处理，判断是否能发送，用于实现防火墙之类的策略
            __ip_local_out(net, sk, skb);
            {
                skb->protocol = htons(ETH_P_IP);
                return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, net, sk, skb, ...);
                {
                    nf_hook_slow(skb, &state, hook_head, 0);
                    {
                        for (; s < e->num_hook_entries; s++) {
                            verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
                            switch (verdict & NF_VERDICT_MASK) {
                            case NF_ACCEPT:
                                break;
                            case NF_DROP:
                                kfree_skb(skb);
                                return -EPERM;
                            case NF_QUEUE:
                                ret = nf_queue(skb, state, s, verdict);
                                if (ret == 1)
                                    continue;
                                return ret;
                            default:
                                return 0;
                            }
                        }
                    }
                }
            }

            dst_output(net, sk, skb);
            {
                // 在前面路由时已经设置rth->dst.output = ip_output;
                skb_dst(skb)->output(net, sk, skb);
                {
                    skb->dev = dev;
	                skb->protocol = htons(ETH_P_IP);
                    ip_finish_output(net, sk, skb);
                    {
                        // cgroup可以限制网络流量
                        // int ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
                        // switch (ret) {
                        // case NET_XMIT_SUCCESS:
                        //     return __ip_finish_output(net, sk, skb);
                        // case NET_XMIT_CN:
                        //     return __ip_finish_output(net, sk, skb) ? : ret;
                        // default:
                        //     kfree_skb(skb);
                        //     return ret;
                        // }
                        __ip_finish_output(net, sk, skb);
                        {
                            unsigned int mtu = ip_skb_dst_mtu(sk, skb);
                            if (skb->len > mtu || IPCB(skb)->frag_max_size) {
                                // 超过mtu则分片后再发送
                                ip_fragment(net, sk, skb, mtu, ip_finish_output2);
                                {
                                    struct iphdr *iph = ip_hdr(skb);

                                    // 非禁止分片
                                    if ((iph->frag_off & htons(IP_DF)) == 0)
                                        return ip_do_fragment(net, sk, skb, output);

                                    if (unlikely(!skb->ignore_df ||
                                            (IPCB(skb)->frag_max_size &&
                                             IPCB(skb)->frag_max_size > mtu))) {
                                        // 设置了禁止分片则发送icmp: ICMP_FRAG_NEEDED
                                        icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
                                        kfree_skb(skb);
                                        return -EMSGSIZE;
                                    }

                                    return ip_do_fragment(net, sk, skb, output);
                                }
                            } else {
                                ip_finish_output2(net, sk, skb);
                            }                                
                        }
                    }
                }
            }
        }
    }
}
```

### 路由算法

### 分片算法



## 邻居子系统

ip协议在路由之后知道了网关ip，包的发送依赖链路层，链路层发包依赖mac地址，所以需要arp协议把ip转成mac地址

```c
int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    // 从邻居子系统查找
    struct neighbour *neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
    {
        // 查找缓存: 缓存会定时刷新
        neigh = __ipv4_neigh_lookup_noref(dev, daddr);
        if (unlikely(!neigh)) {
            // 根据ip查找mac并缓存
            neigh = __neigh_create(&arp_tbl, &daddr, dev, false);
            {
                neigh = neigh_alloc(tbl, dev, exempt_from_gc);
                // arp初始化neighbour: .constructor	= arp_constructor
                arp_tbl->constructor(n);
                {
                    struct net_device *dev = neigh->dev;
                    if (dev->header_ops->cache)
                        neigh->ops = &arp_hh_ops;
                    else
                        neigh->ops = &arp_generic_ops;

                    if (neigh->nud_state & NUD_VALID)
                        neigh->output = neigh->ops->connected_output;
                    else
                        neigh->output = neigh->ops->output;
                }
            }
        }
    }

    neigh_output(neigh, skb, is_v6gw);
    {
        // neigh创建时已设置.output = neigh_resolve_output
        n->output(neigh, skb);
        {
            // 发送arp
            neigh_event_send(neigh, skb);

            // 等待结果
            do {
                __skb_pull(skb, skb_network_offset(skb));
                seq = read_seqbegin(&neigh->ha_lock);
                err = dev_hard_header(skb, dev, ntohs(skb->protocol), neigh->ha, NULL, skb->len);
            } while (read_seqretry(&neigh->ha_lock, seq));

            if (err >= 0)
                // 发送给L2层
                rc = dev_queue_xmit(skb);
            else
                goto out_kfree_skb;
        }
    }
}
```

## L2

`L2`层对应链路层，由`网卡驱动`实现，本文以intel千兆网卡`e1000`的驱动为例。

```c
int dev_queue_xmit(struct sk_buff *skb)
{
    // 选择设备队列: e1000只有一个发送队列
	struct netdev_queue *txq = netdev_core_pick_tx(dev, skb, sb_dev);
    struct Qdisc *q = rcu_dereference_bh(txq->qdisc);
    if (q->enqueue) {
		__dev_xmit_skb(skb, q, dev, txq);
        {
            // 队列允许在空闲时直接发送
            if (q->flags & TCQ_F_CAN_BYPASS && nolock_qdisc_is_empty(q) && qdisc_run_begin(q)) {
                sch_direct_xmit(skb, q, dev, txq, ...);
                {
                    dev_hard_start_xmit(skb, dev, txq, ...);
                    {
                        xmit_one(skb, dev, txq, ...);
                        {
                            netdev_start_xmit(skb, dev, txq, more);
                            {
                                dev->netdev_ops->ndo_start_xmit(skb, dev);
                            }
                        }
                    }
                }
            }

            // 加入发送队列
            q->enqueue(skb, q, ...);
            // 处理队列
            qdisc_run(q);
            {
                // 发送一个队列中的skb: sch_direct_xmit
                while (qdisc_restart(q, &packets)) {
                    quota -= packets;
                    if (quota <= 0) {
                        // 超过发送限额，触发软中断
                        __netif_schedule(q);
                        {
                            // 挪到调度队列尾
                            struct softnet_data *sd = this_cpu_ptr(&softnet_data);
                            q->next_sched = NULL;
                            *sd->output_queue_tailp = q;
                            sd->output_queue_tailp = &q->next_sched;

                            // 触发软中断
                            raise_softirq_irqoff(NET_TX_SOFTIRQ);
                        }
                        break;
                    }
                }
            }
        }
	}
}
```

## tx软中断

```c
static int __init net_dev_init(void)
{
    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
}

void net_tx_action(struct softirq_action *h)
{
    struct softnet_data *sd = this_cpu_ptr(&softnet_data);
    if (sd->completion_queue) {
        clist = sd->completion_queue;
        while (clist) {
            struct sk_buff *skb = clist;
			clist = clist->next;
            // 释放发送完成的skb
            __kfree_skb(skb);
        }
    }

    if (sd->output_queue) {
        struct Qdisc *head;

		local_irq_disable();
		head = sd->output_queue;
		sd->output_queue = NULL;
		sd->output_queue_tailp = &sd->output_queue;
		local_irq_enable();

        while (head) {
            struct Qdisc *q = head;
            head = head->next_sched;
            // 发送skb直到到达限额
            qdisc_run(q);
        }
    }
}
```

# e1000网卡驱动

## 驱动注册

```c
static struct pci_driver e1000_driver = {
	.name     = e1000_driver_name,
	.id_table = e1000_pci_tbl,
	.probe    = e1000_probe,
	.remove   = e1000_remove,
	.driver = {
		.pm = &e1000_pm_ops,
	},
	.shutdown = e1000_shutdown,
	.err_handler = &e1000_err_handler
};

static int __init e1000_init_module(void)
{
    pci_register_driver(&e1000_driver);
}
```

## 设备初始化

```c
static const struct net_device_ops e1000_netdev_ops = {
	.ndo_open				= e1000_open,
	.ndo_stop				= e1000_close,
	.ndo_start_xmit			= e1000_xmit_frame,
	.ndo_change_mtu			= e1000_change_mtu,
};

static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    // 创建net_device, 默认rx/tx都是一个队列
    struct net_device *netdev = alloc_etherdev(sizeof(struct e1000_adapter));
    netdev->netdev_ops = &e1000_netdev_ops;
    // 加入napi轮询列表
    netif_napi_add(netdev, &adapter->napi, e1000_clean, 64);
    // 硬件初始化
    e1000_sw_init(adapter);
    {
        // 能接收的最大包长度
        adapter->rx_buffer_len = 1522;
        // 队列个数
        adapter->num_tx_queues = 1;
        adapter->num_rx_queues = 1;
        // 创建队列
        e1000_alloc_queues(adapter);
        // 禁用中断
        e1000_irq_disable(adapter);
    }
}
```

## 启动设备

```c
int e1000_open(struct net_device *netdev)
{
    e1000_setup_all_tx_resources(adapter);
    {
        // 初始化每个队列
        for (i = 0; i < adapter->num_tx_queues; i++) {
		    e1000_setup_tx_resources(adapter, &adapter->tx_ring[i]);
            {
                // e1000_tx_buffer用于存储skb和dma_addr_t的对应关系
                int size = sizeof(struct e1000_tx_buffer) * txdr->count;
	            txdr->buffer_info = vzalloc(size);

                // 按page对齐
                txdr->size = txdr->count * sizeof(struct e1000_tx_desc);
	            txdr->size = ALIGN(txdr->size, 4096);

                // dma-mapping
                txdr->desc = dma_alloc_coherent(&pdev->dev, txdr->size, &txdr->dma, GFP_KERNEL);
            }
        }
    }

    e1000_setup_all_rx_resources(adapter);
    {
        for (i = 0; i < adapter->num_rx_queues; i++) {
		    e1000_setup_rx_resources(adapter, &adapter->rx_ring[i]);
            {
                // e1000_rx_buffer用于存储skb和dma_addr_t的对应关系
                int size = sizeof(struct e1000_rx_buffer) * rxdr->count;
	            rxdr->buffer_info = vzalloc(size);

                rxdr->size = rxdr->count * sizeof(struct e1000_rx_desc);
	            rxdr->size = ALIGN(rxdr->size, 4096);

                // dma-mapping
                rxdr->desc = dma_alloc_coherent(&pdev->dev, rxdr->size, &rxdr->dma, GFP_KERNEL);
            }
        }
    }

    // 注册irq
    e1000_request_irq(adapter);
    {
        irq_handler_t handler = e1000_intr;
        request_irq(adapter->pdev->irq, handler, irq_flags, netdev->name, netdev);
    }

    // 打开中断
    e1000_irq_enable(adapter);
	netif_start_queue(netdev);
}
```

## 发送skb

```c
static netdev_tx_t e1000_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
    // ip报文分片
    unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
    struct e1000_tx_ring *tx_ring = adapter->tx_ring;
    // gso用于合并多个ip报文
    unsigned int mss = skb_shinfo(skb)->gso_size;
    unsigned int max_per_txd = 4096;

    e1000_tx_map(adapter, tx_ring, skb, first, max_per_txd, nr_frags, mss);
    {
        unsigned int i = tx_ring->next_to_use;

        unsigned int len = skb_headlen(skb);
        unsigned int offset = 0

        while (len) {
            struct e1000_tx_buffer *buffer_info = &tx_ring->buffer_info[i];
            size = min(len, max_per_txd);
            // 以4k为单位map skb的数据
            buffer_info->dma = dma_map_single(&pdev->dev, skb->data + offset, size, DMA_TO_DEVICE);
            len -= size;
		    offset += size;
        }

        for (f = 0; f < nr_frags; f++) {
            const skb_frag_t *frag = &skb_shinfo(skb)->frags[f];

            len = skb_frag_size(frag);
            offset = 0;

            while (len) {
                // 以4k为单位map每个分片的数据
                buffer_info->dma = skb_frag_dma_map(&pdev->dev, frag, offset, size, DMA_TO_DEVICE);
                len -= size;
			    offset += size;
            }
        }

        tx_ring->buffer_info[i].skb = skb;
    }
}
```

# 接收

## 设备中断

网卡在接收到数据包时会触发软中断通知驱动处理数据

```c
static irqreturn_t e1000_intr(int irq, void *data)
{
    /* 先禁用中断切换到轮询模式，避免高速网卡产生中断风暴 */
	ew32(IMC, ~0);
	E1000_WRITE_FLUSH();

    // 是否首次设置NAPIF_STATE_SCHED, 如果是首次则开始轮询
    if (likely(napi_schedule_prep(&adapter->napi))) {
		__napi_schedule(&adapter->napi);
        {
            // 加入poll_list，触发tx软中断
            list_add_tail(&napi->poll_list, &sd->poll_list);
	        __raise_softirq_irqoff(NET_RX_SOFTIRQ);
        }
	}
}
```

## rx软中断

```c
static void net_rx_action(struct softirq_action *h)
{
    LIST_HEAD(list);
    local_irq_disable();
    // 通过修改链表头复制队列
	list_splice_init(&sd->poll_list, &list);
	local_irq_enable();

    for (;;) {
        struct napi_struct *n = list_first_entry(&list, struct napi_struct, poll_list);
		budget -= napi_poll(n, &repoll);
        // 限额用完或超时则结束循环
        if (unlikely(budget <= 0 ||
			     time_after_eq(jiffies, time_limit))) {
			sd->time_squeeze++;
			break;
		}
    }

    // 没处理完的跟新增的合并
    list_splice_tail_init(&sd->poll_list, &list);
	list_splice_tail(&repoll, &list);
	list_splice(&list, &sd->poll_list);

    // 非空则这次触发软中断
	if (!list_empty(&sd->poll_list))
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```

`e1000`注册的`poll`函数是`e1000_clean`

```c
static int e1000_clean(struct napi_struct *napi, int budget)
{
    struct e1000_adapter *adapter = container_of(napi, struct e1000_adapter, napi);
    // 发送完成回收dma资源
    e1000_clean_tx_irq(adapter, &adapter->tx_ring[0]);

    // adapter->clean_rx = e1000_clean_rx_irq;
    adapter->clean_rx(adapter, &adapter->rx_ring[0], &work_done, budget);
    {
        i = rx_ring->next_to_clean;
        rx_desc = E1000_RX_DESC(*rx_ring, i);
        buffer_info = &rx_ring->buffer_info[i];

        // dma处理接收完成的描述符
        while (rx_desc->status & E1000_RXD_STAT_DD) {
            length = le16_to_cpu(rx_desc->length);
            data = buffer_info->rxbuf.data;
            skb = e1000_copybreak(adapter, buffer_info, length, data);
            {
                skb = e1000_alloc_rx_skb(adapter, length);
                dma_sync_single_for_cpu(&adapter->pdev->dev, buffer_info->dma, length, DMA_FROM_DEVICE);
                skb_put_data(skb, data, length);
            }

            e1000_receive_skb(adapter, status, rx_desc->special, skb);
            {
                skb->protocol = eth_type_trans(skb, adapter->netdev);
                // gro = Generic Receive Offload，合并多个小的数据包
                // By reassembling small packets into larger ones, 
                // GRO enables applications to process fewer large packets directly, 
                // thus reducing the number of packets to be processed.
                napi_gro_receive(&adapter->napi, skb);
                {
                    gro_normal_one(napi, skb, 1);
                    {
                        // 根据skb->protocol传给上层协议处理
                        __netif_receive_skb_list(head);
                    }
                }
            }
        }
    }

    // 轮询完毕重新打开中断
    if (likely(napi_complete_done(napi, work_done))) {
        e1000_irq_enable(adapter);
    }
}
```

## L2

```c
static void __netif_receive_skb_list(struct list_head *head)
{
    __netif_receive_skb_core(&skb, ...);
    {
        list_for_each_entry_safe(skb, next, head, list) {
            struct net_device *orig_dev = skb->dev;
            struct packet_type *pt_prev = NULL;

            // pt_prev表示协议族列表的最后一个协议
            __netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
            {
                // 传给对应的协议族处理，空出最后一个由调用方处理
                list_for_each_entry_rcu(ptype, &ptype_all, list) {
                    if (pt_prev)
                        deliver_skb(skb, pt_prev, orig_dev);
                        {
                            pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
                        }
                    pt_prev = ptype;
                }
            }

            // 合并协议族相同的多个连续的skb
            if (pt_curr != pt_prev || od_curr != orig_dev) {
                // 协议族变化批量处理
                __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
                INIT_LIST_HEAD(&sublist);
                pt_curr = pt_prev;
                od_curr = orig_dev;
            }
            list_add_tail(&skb->list, &sublist);
        }

        // 最后最后一批
        __netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);
    }
}
```

## L3

注册协议族

```c
static struct packet_type ip_packet_type = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,
	.list_func = ip_list_rcv,
};

static int __init inet_init(void)
{
    dev_add_pack(&ip_packet_type);
}
```

```c
void ip_list_rcv(struct list_head *head, struct packet_type *pt,
		 struct net_device *orig_dev)
{
    INIT_LIST_HEAD(&sublist);
	list_for_each_entry_safe(skb, next, head, list) {
		struct net_device *dev = skb->dev;
		struct net *net = dev_net(dev);

		skb_list_del_init(skb);
		skb = ip_rcv_core(skb, net);
		if (skb == NULL)
			continue;

        // 合并多个连续的dev相同的skb批量处理
		if (curr_dev != dev || curr_net != net) {
			// dev变化批量处理
			if (!list_empty(&sublist))
				ip_sublist_rcv(&sublist, curr_dev, curr_net);
			INIT_LIST_HEAD(&sublist);
			curr_dev = dev;
			curr_net = net;
		}
		list_add_tail(&skb->list, &sublist);
	}

	if (!list_empty(&sublist))
		ip_sublist_rcv(&sublist, curr_dev, curr_net);
        {
            // 先经过netfilter处理
            NF_HOOK_LIST(NFPROTO_IPV4, NF_INET_PRE_ROUTING, net, ...);
            ip_list_rcv_finish(net, NULL, head);
            {
                list_for_each_entry_safe(skb, next, head, list) {
                    struct net_device *dev = skb->dev;
                    // 查找路由信息
                    ip_rcv_finish_core(net, sk, skb, dev, hint);
                    {
                        ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, dev);
                        {
                            // 查找路由判断目标地址是否属于本机
                            fib_lookup(net, &fl4, res, 0);

                            if (res->type == RTN_LOCAL) {
                                // 本机处理
                                rt_dst_alloc(ip_rt_get_dev(net, res), flags | RTCF_LOCAL, ...);
                                if (flags & RTCF_LOCAL)
			                        rt->dst.input = ip_local_deliver;
                            } else {
                                // 包转发
                                ip_mkroute_input(skb, res, in_dev, daddr, saddr, tos, flkeys);
                                {
                                    rth->dst.input = ip_forward;
                                }
                            }
                        }
                    }

                    // 发给同一个目标的多个连续skb批量处理
                    dst = skb_dst(skb);
                    if (curr_dst != dst) {
                        // 目标变化批量处理
                        if (!list_empty(&sublist))
                            ip_sublist_rcv_finish(&sublist);
                        INIT_LIST_HEAD(&sublist);
                        curr_dst = dst;
                    }
                    list_add_tail(&skb->list, &sublist);
                }

                ip_sublist_rcv_finish(&sublist);
                {
                    list_for_each_entry_safe(skb, next, head, list) {
                        // 此处只展示本机处理的流程
                        dst_input(skb);
                        {
                            // ip分片组装
                            if (ip_is_fragment(ip_hdr(skb))) {
                                // 非0表示片段还没有收全或校验未通过
                                if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
                                    return 0;
                            }

                            // 先经过netfilter再处理
                            return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, ..., ip_local_deliver_finish);
                            {
                                // 根据header中的L4协议派发处理
                                ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
                            }
                        }
                    }
                }
            }
        }
}
```

L3根据header中L4协议的类型派发

```c
static struct net_protocol tcp_protocol = {
	.early_demux	=	tcp_v4_early_demux,
	.early_demux_handler =  tcp_v4_early_demux,
	.handler		=	tcp_v4_rcv,
	.err_handler	=	tcp_v4_err,
	.no_policy		=	1,
	.icmp_strict_tag_validation = 1,
};

static int __init inet_init(void)
{
    inet_add_protocol(&udp_protocol, IPPROTO_UDP);
    inet_add_protocol(&tcp_protocol, IPPROTO_TCP);   
}

void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
    // 查找L4协议
    struct net_protocol *ipprot = rcu_dereference(inet_protos[protocol]);
    ipprot->handler(skb);
}
```

## L4

```c
int tcp_v4_rcv(struct sk_buff *skb)
{
    th = (const struct tcphdr *)skb->data;
	iph = ip_hdr(skb);
    // 根据(saddr, sport, daddr, dport)查找sock
    sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source, th->dest, sdif, ...);

    // 各种限制和策略的检查
    if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
		goto discard_and_relse;
	}

    if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;

	if (tcp_filter(sk, skb))
		goto discard_and_relse;

    // tcp状态机
    tcp_v4_do_rcv(sk, skb);
}
```

# socket

# 连接建立

# 连接断开

# 状态机

# 定时器




