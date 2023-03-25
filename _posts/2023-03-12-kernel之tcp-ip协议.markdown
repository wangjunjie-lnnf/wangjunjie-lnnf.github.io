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
    th->source        = inet->inet_sport;
    th->dest        = inet->inet_dport;
    th->seq            = htonl(tcb->seq);
    th->ack_seq        = htonl(tcp_sk(sk)->rcv_nxt);
    // 设置header长度和flag
    *(((__be16 *)th) + 6)    = htons(((tcp_header_size >> 2) << 12) | tcb->tcp_flags);

    if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
        th->window  = htons(tcp_select_window(sk));
        // 拥堵标识
        tcp_ecn_send(sk, skb, th, tcp_header_size);
    } else {
        th->window    = htons(min(tp->rcv_wnd, 65535U));
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
#define IP_CE        0x8000        /* Flag: "Congestion"        */
#define IP_DF        0x4000        /* Flag: "Don't Fragment"    */
#define IP_MF        0x2000        /* Flag: "More Fragments"    */
#define IP_OFFSET    0x1FFF        /* "Fragment Offset" part    */
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
                // Destination        Gateway            Flags           Netif             Expire
                // default            10.0.64.1          UGScg             en0       
                // 192.168.1.0/24      192.168.1.1         UCS               lo0    
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

When the `IP` layer in a host or router needs to send an IP datagram to a next-hop router or host, it first examines the destination IP address (D) in the datagram. Using the value D, the following `longest prefix match` algorithm is executed on the forwarding table:

1. Search the table for all entries for which the following property holds: `(D ^ mj) = dj`, where `mj` is the value of the `mask field` associated with the forwarding entry `ej` having index `j`, and `dj` is the value of the destination field associated with `ej`. This means that the destination IP address D is `bitwise ANDed` with the mask in each forwarding table entry (mj), and the result is compared against the destination in the same forwarding table entry (dj). If the property holds, the entry (ej here) is a “match” for the destination IP address. When a match happens, the algorithm notes the entry index (j here) and how many bits in the mask mj were set to 1. The more bits set to 1, the “better” the match.

从IP报文头取出目标地址D，跟路由表中的每个路由项的子网掩码做and运算，结果跟此路由项的地址对比，计算匹配的最大长度。

2. The best matching entry ek (i.e., the one with the largest number of 1 bits in its mask mk) is selected, and its next-hop field nk is used as the next-hop IP address in forwarding the datagram.

If no matches in the forwarding table are found, the datagram is undeliverable. If the undeliverable datagram was generated locally (on this host), a `“host unreach- able”` error is normally returned to the application that generated the datagram. On a router, an `ICMP` message is normally sent back to the host that sent the datagram.

### 分片算法

When an IPv4 datagram is fragmented into multiple smaller fragments, each of which itself is an independent IP datagram, `the Total Length field reflects the length of the particular fragment`.

The `Identification field` helps indentify each datagram sent by an IPv4 host. To ensure that the fragments of one datagram are not confused with those of another, the sending host normally increments an internal counter by 1 each time a datagram is sent (from one of its IP addresses) and copies the value of the counter into the IPv4 Identification field.

The `Identification field` value (set by the original sender) is copied to each fragment and is used to group them together when they arrive. The `Fragment Offset` field gives the offset of the first byte of the fragment payload byte in the original IPv4 datagram (`in 8-byte units`). Clearly, the first fragment always has offset 0.

`Identification`字段用于标识多个分片属于同一个datagram


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
                // arp初始化neighbour: .constructor    = arp_constructor
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
    .ndo_open                = e1000_open,
    .ndo_stop                = e1000_close,
    .ndo_start_xmit            = e1000_xmit_frame,
    .ndo_change_mtu            = e1000_change_mtu,
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
    .early_demux    =    tcp_v4_early_demux,
    .early_demux_handler =  tcp_v4_early_demux,
    .handler        =    tcp_v4_rcv,
    .err_handler    =    tcp_v4_err,
    .no_policy        =    1,
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

    // tcp状态机，此处只展示连接建立之后的流程
    tcp_v4_do_rcv(sk, skb);
    {
        if (sk->sk_state == TCP_ESTABLISHED) {
            tcp_rcv_established(sk, skb);
            {
                // 校验时间戳和seq等
                tcp_validate_incoming(sk, skb, th, 1);

                // 处理收到的ack
                tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT);
                {
                    // 更新滑动窗口
                    tcp_ack_update_window(sk, skb, ack, ack_seq);
                    // 清理retransmit queue
                    tcp_clean_rtx_queue(sk, skb, prior_fack, prior_snd_una, &sack_state, flag & FLAG_ECE);
                    // 拥堵控制
                    tcp_cong_control(sk, ack, delivered, flag, sack_state.rate);
                }

                // 更新rtt
                tcp_rcv_rtt_measure_ts(sk, skb);

                tcp_data_queue(sk, skb);
                {
                    // 插入sk->sk_receive_queue
                    tcp_queue_rcv(sk, skb, &fragstolen);
                }
            }
        }
    }
}
```

# 状态机

The rules that determine what TCP does are determined by what state TCP is in. The current state is changed based on various stimuli, such as segments that are transmitted or received, timers that expire, application reads or writes, or information from other layers.

tcp状态机
![tcp-state-1](/assets/images/2023-03-12/tcp-state-1.png)

连接建立和断开对应的状态
![tcp-state-2](/assets/images/2023-03-12/tcp-state-2.png)

When initialized, TCP starts in the `CLOSED` state. Usually an immediate transition takes it to either the `SYN_SENT` or `LISTEN` state, depending on whether the TCP is asked to perform an active or passive open, respectively.

`TIME_WAIT`是一个非常特殊的状态

The `TIME_WAIT` state is also called the `2MSL wait state`. It is a state in which TCP waits for a time equal to twice the `Maximum Segment Lifetime (MSL)`, sometimes called timed wait. Every implementation must choose a value for the MSL. It is the maximum amount of time any segment can exist in the network before being discarded. [RFC0793] specifies the `MSL` as `2 minutes`. Common implementation values, however, are `30s`, `1 minute`, or `2 minutes`. In most cases, the value can be modified. On Linux, the value `net.ipv4.tcp_fin_timeout`(`default 60`) holds the 2MSL wait timeout value (`in seconds`).

Given the MSL value for an implementation, the rule is: When TCP performs an active close and sends the final ACK, that connection must stay in the `TIME_ WAIT` state for twice the MSL. This lets TCP resend the final ACK in case it is lost. TCP will always retransmit FINs until it receives a final ACK.

Another effect of this 2MSL wait state is that while the TCP implementation waits, the endpoints defining that connection (`client IP address, client port number, server IP address, and server port number`) cannot be reused. That connection can be reused only when the 2MSL wait is over. Most implementations and APIs provide a way to bypass this restriction. With the Berkeley sockets API, the `SO_REUSEADDR` socket option enables the bypass operation. It lets the caller assign itself a local port number even if that port number is part of some connection in the 2MSL wait state. 

`SO_REUSEADDR`可以绕过`TIME_WAIT`的限制。

For interactive applications, it is normally the client that does the active close and enters the `TIME_WAIT` state. The server usually does the passive close and does not go through the TIME_WAIT state. The implication is that if we terminate a client, and restart the same client immediately, that new client cannot reuse the same local port number. This is not ordinarily a problem, because `clients normally use ephemeral ports assigned by the operating system` and do not care what the assigned port number is.

`TIME_WAIT`对client的影响很小，因为client每次都使用随机端口。

With servers, however, the situation is different. They almost always use well-known ports. If we terminate a server process that has a connection established and immediately try to restart it, the server cannot assign its assigned port number to its endpoint (it gets an “`Address already in use`” binding error), because that port number is part of a connection that is in a 2MSL wait state. It may take from 1 to 4 minutes for the server to be able to restart, depending on the local system’s value for the MSL.

`TIME_WAIT`状态下重用端口会提示`Address already in use`。

# socket

## 注册文件系统

```c
static struct vfsmount *sock_mnt;

static struct file_system_type sock_fs_type = {
    .name =        "sockfs",
    .init_fs_context = sockfs_init_fs_context,
    .kill_sb =    kill_anon_super,
};

static int __init sock_init(void)
{
    register_filesystem(&sock_fs_type);
    // 直接挂载
    sock_mnt = kern_mount(&sock_fs_type);
}

static const struct super_operations sockfs_ops = {
    .alloc_inode    = sock_alloc_inode,
    .free_inode        = sock_free_inode,
    .statfs            = simple_statfs,
};

// 初始化super_block
static int sockfs_init_fs_context(struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = init_pseudo(fc, SOCKFS_MAGIC);s
    ctx->ops = &sockfs_ops;
    ctx->dops = &sockfs_dentry_operations;
    ctx->xattr = sockfs_xattr_handlers;
    return 0;
}

// 创建inode
static struct inode *sock_alloc_inode(struct super_block *sb)
{
    struct socket_alloc *ei = kmem_cache_alloc(sock_inode_cachep, GFP_KERNEL);
    init_waitqueue_head(&ei->socket.wq.wait);
    
    ei->socket.state = SS_UNCONNECTED;
    ei->socket.flags = 0;

    // inode嵌入在socket_alloc中
    return &ei->vfs_inode;
}

```

## 注册协议族

```c
static struct net_proto_family *net_families[46];

static const struct net_proto_family inet_family_ops = {
    .family = PF_INET,
    .create = inet_create,
    .owner    = THIS_MODULE,
};

sock_register(&inet_family_ops);
```

## 注册协议

```c
static struct list_head inetsw[11];

struct proto tcp_prot = {
    .name            = "TCP",
    .close            = tcp_close,
    .pre_connect    = tcp_v4_pre_connect,
    .connect        = tcp_v4_connect,
    .disconnect        = tcp_disconnect,
    .accept            = inet_csk_accept,
    .ioctl            = tcp_ioctl,
    .init            = tcp_v4_init_sock,
    .destroy        = tcp_v4_destroy_sock,
    .shutdown        = tcp_shutdown,
    .setsockopt        = tcp_setsockopt,
    .getsockopt        = tcp_getsockopt,
    .keepalive        = tcp_set_keepalive,
    .recvmsg        = tcp_recvmsg,
    .sendmsg        = tcp_sendmsg,
    .sendpage        = tcp_sendpage,
    .backlog_rcv    = tcp_v4_do_rcv,
    .release_cb        = tcp_release_cb,
    .hash            = inet_hash,
    .unhash            = inet_unhash,
    .get_port        = inet_csk_get_port
};

const struct proto_ops inet_dgram_ops = {
    .family           = PF_INET,
    .release       = inet_release,
    .bind           = inet_bind,
    .connect       = inet_dgram_connect,
    .socketpair       = sock_no_socketpair,
    .accept           = sock_no_accept,
    .getname       = inet_getname,
    .poll           = udp_poll,
    .ioctl           = inet_ioctl,
    .gettstamp       = sock_gettstamp,
    .listen           = sock_no_listen,
    .shutdown       = inet_shutdown,
    .setsockopt       = sock_common_setsockopt,
    .getsockopt       = sock_common_getsockopt,
    .sendmsg       = inet_sendmsg,
    .read_sock       = udp_read_sock,
    .recvmsg       = inet_recvmsg,
    .mmap           = sock_no_mmap,
    .sendpage       = inet_sendpage,
    .set_peek_off       = sk_set_peek_off,
};

static struct inet_protosw inetsw_array[] =
{
    {
        .type =       SOCK_STREAM,
        .protocol =   IPPROTO_TCP,
        .prot =       &tcp_prot,
        .ops =        &inet_stream_ops,
        .flags =      INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
    },

    {
        .type =       SOCK_DGRAM,
        .protocol =   IPPROTO_UDP,
        .prot =       &udp_prot,
        .ops =        &inet_dgram_ops,
        .flags =      INET_PROTOSW_PERMANENT,
    },

    {
        .type =       SOCK_DGRAM,
        .protocol =   IPPROTO_ICMP,
        .prot =       &ping_prot,
        .ops =        &inet_sockraw_ops,
        .flags =      INET_PROTOSW_REUSE,
    },

    {
        .type =       SOCK_RAW,
        .protocol =   IPPROTO_IP,    /* wild card */
        .prot =       &raw_prot,
        .ops =        &inet_sockraw_ops,
        .flags =      INET_PROTOSW_REUSE,
    }
};

for (q = inetsw_array; q < &inetsw_array[4]; ++q)
    inet_register_protosw(q);
```

## 系统调用

### socket

```c
static const struct file_operations socket_file_ops = {
    .read_iter =    sock_read_iter,
    .write_iter =    sock_write_iter,
    .poll =            sock_poll
};

int __sys_socket(int family, int type, int protocol)
{
    sock_create(family, type, protocol, &sock);
    {
        struct socket *sock = sock_alloc();
        sock->type = type;

        struct net_proto_family *pf = net_families[family];
        // 使用指定的协议族初始化socket: inet_create
        pf->create(net, sock, protocol, kern);
        {
            // 查找协议族下的协议
            struct inet_protosw *answer = inetsw[sock->type];
            sock->ops = answer->ops;

            struct sock *sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer->prot, kern);
            {
                sk = sk_prot_alloc(prot, priority | __GFP_ZERO, family);
                sk->sk_family = family;
                sk->sk_prot = sk->sk_prot_creator = prot;
            }

            sock_init_data(sock, sk);
            {
                // 默认可以放下256个skb
                sk->sk_rcvbuf =    sysctl_rmem_default;
                sk->sk_sndbuf =    sysctl_wmem_default;
                sk->sk_state = TCP_CLOSE;
            }
        }
    }

    sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
    {
        struct file *file = sock_alloc_file(sock, flags, NULL);
        {
            file = alloc_file_pseudo(SOCK_INODE(sock), ..., &socket_file_ops);

            sock->file = file;
            file->private_data = sock;
        }
    }
}
```

### bind

```c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    struct socket *sock = sockfd_lookup_light(fd, ...);
    sock->ops->bind(sock, (struct sockaddr *)&address, addrlen);
    {
        struct net *net = sock_net(sock->sk);
        inet->inet_saddr = addr->sin_addr.s_addr;

        // 检查端口是否可用: inet_csk_get_port
        sk->sk_prot->get_port(sk, snum);
        {
            // 查找hash表
            head = &hinfo->bhash[inet_bhashfn(net, port, hinfo->bhash_size)];
            inet_bind_bucket_for_each(tb, &head->chain)
                if (net_eq(ib_net(tb), net) && tb->l3mdev == l3mdev && tb->port == port) {
                    // 端口
                    if (sk->sk_reuse == SK_FORCE_REUSE) {
                        return success;
                    } 
                    // 检查是否能绑定正在使用的端口
                    if (inet_csk_bind_conflict(sk, tb, true, true)) {
                        return fail;
                    }
                }
            // 创建记录插入hash表
            inet_bind_bucket_create(hinfo->bind_bucket_cachep, net, head, port, l3mdev);
        }

        inet->inet_sport = htons(inet->inet_num);
        inet->inet_daddr = 0;
        inet->inet_dport = 0;
    }
}
```

### listen

```c
int __sys_listen(int fd, int backlog)
{
    struct socket *sock = sockfd_lookup_light(fd, ...);

    // inet_listen
    sock->ops->listen(sock, backlog);
    {
        inet_csk_listen_start(sk, backlog);
        {
            struct inet_connection_sock *icsk = inet_csk(sk);
            struct inet_sock *inet = inet_sk(sk);
            // 创建accept队列
            reqsk_queue_alloc(&icsk->icsk_accept_queue);
            // 修改状态
            inet_sk_state_store(sk, TCP_LISTEN);
            // 又检查端口
            sk->sk_prot->get_port(sk, inet->inet_num);
        }
    }
}
```

### connect

```c
int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    // inet_stream_connect
    sock->ops->connect(sock, (struct sockaddr *)address, addrlen, ...);
    {
        // tcp_v4_connect
        sk->sk_prot->connect(sk, uaddr, addr_len);

        sock->state = SS_CONNECTING;

        // 阻塞时长
        timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

        // 3次握手已经进行中
        if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
            if (!timeo) {
                return;
            } 

            // 等待超时
            inet_wait_for_connect(sk, timeo, ...);
            {
                while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
                    release_sock(sk);
                    timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
                    lock_sock(sk);
                    // 被signal打断或超时
                    if (signal_pending(current) || !timeo)
                        break;
                }
            }
        }
    }
}
```

### accept

```c
int __sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr,
          int __user *upeer_addrlen, int flags)
{
    struct file *newfile = do_accept(file, file_flags, upeer_sockaddr, upeer_addrlen, flags);
    {
        // server socket
        sock = sock_from_file(file);
        // child socket
        newsock = sock_alloc();

        newsock->type = sock->type;
        newsock->ops = sock->ops;

        // inet_csk_accept
        sock->ops->accept(sock, newsock, sock->file->f_flags | file_flags, false);
        {
            struct request_sock_queue *queue = &icsk->icsk_accept_queue;

            // 如果连接队列为空，等待直到超时
            if (reqsk_queue_empty(queue)) {
                long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
                inet_csk_wait_for_connect(sk, timeo);
            }

            // 从队列里取出一个
            struct request_sock *req = reqsk_queue_remove(queue, sk);
            newsock = req->sk;
        }
    }

    fd_install(newfd, newfile);
    return newfd;
}
```

### shutdown

```c
int __sys_shutdown(int fd, int how)
{
    struct socket *sock = sockfd_lookup_light(fd, ...);
    __sys_shutdown_sock(sock, how);
    {
        // tcp_shutdown
        sock->ops->shutdown(sock, how);
        {
            if ((1 << sk->sk_state) &
                (TCPF_ESTABLISHED | TCPF_SYN_SENT |
                 TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
                if (tcp_close_state(sk))
                    tcp_send_fin(sk);
    }
        }
    }
}
```

### sendmsg

```c
long __sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned int flags, ...)
{
    struct socket *sock = sockfd_lookup_light(fd, ...);

    ___sys_sendmsg(sock, msg, &msg_sys, flags, NULL, 0);
    {
        // tcp_sendmsg
        sock->ops->sendmsg(sock, msg_sys);
        {
            mss_now = tcp_send_mss(sk, &size_goal, flags);

            // 生成skb，复制数据，最多mss，加入发送队列
            while (msg_data_left(msg)) {
                // 生成新的skb
                skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, first_skb);
                // 插入发送队列
                skb_entail(sk, skb);
                // 复制数据
                skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
            }

            // 开始发送
            tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH, size_goal);
            {
                __tcp_push_pending_frames(sk, mss_now, nonagle);
                {
                    tcp_write_xmit(sk, cur_mss, nonagle, 0, sk_gfp_mask(sk, GFP_ATOMIC));
                    {
                        while ((skb = tcp_send_head(sk))) {
                            // 发送一个skb
                            tcp_transmit_skb(sk, skb, 1, gfp);
                        }
                    }
                }
            }
        }
    }
}
```

### recvmsg

```c
long __sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned int flags, ...)
{
    struct socket *sock = sockfd_lookup_light(fd, ...);

    // tcp_recvmsg
    sock->ops->recvmsg(sock, msg_sys, flags);
    {
        tcp_recvmsg_locked(sk, msg, len, nonblock, flags, &tss, &cmsg_flags);
        {
            // 循环读取接收队列的skb，直到满足用户指定的长度
            do {
                skb_queue_walk(&sk->sk_receive_queue, skb) {
                    offset = *seq - TCP_SKB_CB(skb)->seq;
                    // 此skb还有未复制的数据
                    if (offset < skb->len) {
                        used = skb->len - offset;
                        if (len < used)
                            used = len;
                        
                        // 复制数据
                        skb_copy_datagram_msg(skb, offset, msg, used);

                        copied += used;
                        len -= used;
                    }
                }
            } while (len > 0);
        }
    }

}
```

# 连接建立

```c

// client发送syn
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    tcp_set_state(sk, TCP_SYN_SENT);

    // 生成ISN: hash + 时间戳
    tp->write_seq = secure_tcp_seq(inet->inet_saddr,
                                   inet->inet_daddr,
                                   inet->inet_sport,
                                   usin->sin_port);
    {
        hash = siphash_3u32((__force u32)saddr, (__force u32)daddr,
			                (__force u32)sport << 16 | (__force u32)dport, ...);
	    return seq_scale(hash);
        {
            return hash + (ktime_get_real_ns() >> 6);
        }
    }

    tcp_connect(sk);
    {
        buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
        tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
        // 发送syn
        tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);

        // 设置重传计时器
        inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
    }
}

// server接收syc，发送syn+ack
int tcp_v4_rcv(struct sk_buff *skb)
{
    tcp_v4_do_rcv(sk, skb);
    {
        tcp_rcv_state_process(sk, skb);
        {
            switch (sk->sk_state) {
                case TCP_LISTEN:
                    if (th->syn) {
                        icsk->icsk_af_ops->conn_request(sk, skb);
                        {
                            tcp_v4_conn_request(sk, skb);
                            {
                                inet_reqsk_alloc(rsk_ops, sk, !want_cookie);
                                {
                                    struct request_sock *req = reqsk_alloc(ops, sk_listener, attach_listener);
                                    struct inet_request_sock *ireq = inet_rsk(req);
                                    // 是不是很神奇，状态并不是TCP_SYN_RECV
                                    // TCP_SYN_RECV已经被fastopen占用了，所以新增了TCP_NEW_SYN_RECV
                                    ireq->ireq_state = TCP_NEW_SYN_RECV;
                                }

                                if (!want_cookie) {
                                    // TFO stands for TCP Fast Open. 
                                    // It is a transport layer solution for avoiding one full RTT between client and server.
                                    // It avoids TCP-3 way handshake for repeated connections.
                                    // 
                                    // TFO works only for repeat connections because of the requirement of a cryptographic cookie. 
                                    // For the first time when the client interacts with the server then it has to perform 3 way handshake. 
                                    // In that handshake, the server shares a cryptographic cookie with the client. 
                                    // For the next connection onwards, the client just piggybacks the GET(只支持GET，不支持POST) request
                                    // and cookie in the SYN packet itself. 
                                    // Then server authenticates the client using a cookie accepts the connection request 
                                    // and sends the data in the ACK packet.
                                    fastopen_sk = tcp_try_fastopen(sk, skb, req, &foc, dst);
                                    {
                                        tcp_fastopen_create_child(sk, skb, req);
                                        {
                                            inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, ...);
                                            {
                                                tcp_v4_syn_recv_sock(sk, skb, req, ...);
                                                {
                                                    tcp_create_openreq_child(sk, req, skb);
                                                    {
                                                        inet_csk_clone_lock(sk, req, GFP_ATOMIC);
                                                        {
                                                            struct sock *newsk = sk_clone_lock(sk, priority);
                                                            inet_sk_set_state(newsk, TCP_SYN_RECV);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if (fastopen_sk) {
                                    // 发送syn+ack
                                    af_ops->send_synack(sk, dst, &fl, req, ..., skb);
                                    /* Add the child socket directly into the accept queue */
                                    inet_csk_reqsk_queue_add(sk, req, fastopen_sk);
                                } else {
                                    // 把req插入tcp_hashinfo
                                    inet_csk_reqsk_queue_hash_add(sk, req, ...);
                                    // 发送syn+ack
                                    af_ops->send_synack(sk, dst, &fl, req, ..., skb);
                                }
                            }
                        }

                        return 0;
                    }
            }
        }
    }
}

// client收到syn+ack
int tcp_v4_rcv(struct sk_buff *skb)
{
    tcp_v4_do_rcv(sk, skb);
    {
        tcp_rcv_state_process(sk, skb);
        {
            switch (sk->sk_state) {
                case TCP_SYN_SENT:
                    tcp_rcv_synsent_state_process(sk, skb, th);
                    {
                        tcp_finish_connect(sk, skb);
                        {
                            tcp_set_state(sk, TCP_ESTABLISHED);
                        }
                    }
            }
        }
    }
}

// server收到ack
int tcp_v4_rcv(struct sk_buff *skb)
{
    // 根据(saddr, sport, daddr, dport)查找sock
	sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source, th->dest, ...);
    
    // 正常的3次握手
    if (sk->sk_state == TCP_NEW_SYN_RECV) {
        tcp_check_req(sk, skb, req, false, &req_stolen);
        {
            inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, ...);
            {
                // 此处同fastopen
                tcp_v4_syn_recv_sock(sk, skb, req, ...);
                {
                    tcp_create_openreq_child(sk, req, skb);
                    {
                        inet_csk_clone_lock(sk, req, GFP_ATOMIC);
                        {
                            struct sock *newsk = sk_clone_lock(sk, priority);
                            inet_sk_set_state(newsk, TCP_SYN_RECV);
                        }
                    }
                }
            }
        }

        // 插入backlog等待accept
        tcp_child_process(sk, nsk, skb);
        {
            __sk_add_backlog(child, skb);
        }

        return 0;
    }

    tcp_v4_do_rcv(sk, skb);
    {
        tcp_rcv_state_process(sk, skb);
        {
            tcp_ack(sk, skb, ...);

            switch (sk->sk_state) {
                case TCP_SYN_RECV:
                    // fastopen
                    tcp_set_state(sk, TCP_ESTABLISHED);
            }
        }
    }
}

```

# 连接断开

```c
// 关闭连接状态机变化
static const unsigned char new_state[16] = {
  /* current state:    new state:      action:	*/
  [TCP_ESTABLISHED]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  [TCP_SYN_SENT]	= TCP_CLOSE,
  [TCP_SYN_RECV]	= TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  [TCP_FIN_WAIT1]	= TCP_FIN_WAIT1,
  [TCP_FIN_WAIT2]	= TCP_FIN_WAIT2,
  [TCP_TIME_WAIT]	= TCP_CLOSE,
  [TCP_CLOSE]		= TCP_CLOSE,
  [TCP_CLOSE_WAIT]	= TCP_LAST_ACK  | TCP_ACTION_FIN,
  [TCP_LAST_ACK]	= TCP_LAST_ACK,
  [TCP_LISTEN]		= TCP_CLOSE,
  [TCP_CLOSING]		= TCP_CLOSING,
};

// shutdown可以选择发送通道或接收通道
// shutdown没有destory socket
void tcp_shutdown(struct sock *sk, int how)
{
    if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
        
        res = tcp_close_state(sk);
        {
            int next = (int)new_state[sk->sk_state];
            // TCP_ESTABLISHED -> TCP_FIN_WAIT1
            // TCP_CLOSE_WAIT -> TCP_LAST_ACK
            tcp_set_state(sk, ns);
        }

		if (res)
			tcp_send_fin(sk);
	}
}

// close直接destory socket
void __tcp_close(struct sock *sk, long timeout)
{
    res = tcp_close_state(sk);
    {
        int next = (int)new_state[sk->sk_state];
        // TCP_ESTABLISHED -> TCP_FIN_WAIT1
        // TCP_CLOSE_WAIT -> TCP_LAST_ACK
        tcp_set_state(sk, ns);
    }

    if (res)
        tcp_send_fin(sk);
}

int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
    if (sk->sk_state == TCP_ESTABLISHED) {
        tcp_rcv_established(sk, skb);
        {
            tcp_data_queue(sk, skb);
            {
                // 收到FIN标识
                if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			        tcp_fin(sk);
                    {
                        switch (sk->sk_state) {
                            case TCP_ESTABLISHED:
                                tcp_set_state(sk, TCP_CLOSE_WAIT);
                        }
                    }
            }
        }
    }

    tcp_rcv_state_process(sk, skb);
    {
        switch (sk->sk_state) {
        case TCP_FIN_WAIT1:
            tcp_set_state(sk, TCP_FIN_WAIT2);
            break;

        case TCP_CLOSING:
            tcp_time_wait(sk, TCP_TIME_WAIT, 0);
            break;
        case TCP_LAST_ACK:
            tcp_done(sk);
            {
                tcp_set_state(sk, TCP_CLOSE);
            }
            break;
        }

        switch (sk->sk_state) {
            case TCP_CLOSE_WAIT:
            case TCP_CLOSING:
            case TCP_LAST_ACK:
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
            case TCP_ESTABLISHED:
                tcp_data_queue(sk, skb);
                {
                    // 收到FIN标识
                    if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
                        tcp_fin(sk);
                        {
                            switch (sk->sk_state) {
                            case TCP_SYN_RECV:
                            case TCP_ESTABLISHED:
                                tcp_set_state(sk, TCP_CLOSE_WAIT);
                                break;

                            case TCP_FIN_WAIT1:
                                tcp_set_state(sk, TCP_CLOSING);
                                break;

                            case TCP_FIN_WAIT2:
                                tcp_time_wait(sk, TCP_TIME_WAIT, 0);
                                break;
                            }
                        }
                }
        }
    }
}
```

# 拥堵控制

`MSS`决定了一个包的大小，`window`决定了可以发多少`MSS`大小的包，
假设发送方和接收方性能都很强，`window`可以设置成`1G`，
如果中间有个路由器性能很差，处理不了这么快的发送速度呢，只会导致大量丢包和重传，效率低同时浪费带宽。
解决此问题需要再加一个参数：拥堵窗口，拥堵窗口根据丢包情况动态调整，真正的发送窗口取min(wnd, cwnd)。

注册拥堵控制算法

```c
static LIST_HEAD(tcp_cong_list);

// 注册
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    list_add_tail_rcu(&ca->list, &tcp_cong_list);
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= cubictcp_init,
	.ssthresh	= cubictcp_recalc_ssthresh,
	.cong_avoid	= cubictcp_cong_avoid,
	.set_state	= cubictcp_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= cubictcp_cwnd_event,
	.pkts_acked = cubictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

static int __init cubictcp_register(void)
{
    // ubuntu-22默认值
    tcp_register_congestion_control(&cubictcp);
}

struct tcp_congestion_ops tcp_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
};

void __init tcp_init(void)
{
    // 默认值
    tcp_register_congestion_control(&tcp_reno);
}

```





