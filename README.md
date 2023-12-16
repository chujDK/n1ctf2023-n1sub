# n1sub

n1sub 是我为 n1ctf2023 出的一道 Linux kernel 利用题。题目提供了一个内核驱动 sub.ko，可以通过 ioctl 与之交互，提供了 kmalloc，kfree 和 edit 方法。kmalloc 可以申请 sub_size 大小的 slab，使用 GFP_KERNEL_ACCOUNT flag，edit 会在 sub_offset 偏移处的 u32 减一。我在其中埋下了一个 UAF 漏洞，即 kfree 不会清空指针，所以可以用 edit 来实现 UAF。 比较特殊的是 sub_size 和 sub_offset 两个变量都是随机产生的，因此被 UAF 的对象大小是随机的，同时能修改的偏移也是随机的。

预期解不涉及任何爆破，不过由于堆喷存在失败的可能性，所以仍有失败的概率。我一开始写 exp 的时候没有去消除可能存在的噪音，最后实际测试的时候发现成功率还可以（大概在 50% ~ 70%），基本上不影响调试 ，感觉还可以了就没有去消除噪音了，实际上只要在各个 kmem_cache 上都事先 free 几个 slab 应该就可以把成功率提升到接近 100% 了。

预期解使用了 nftables 子系统中的 nft_rule 结构体来进行利用，这个结构体的大小可以由用户进行控制。nft_rule 这个结构体可以达到的最大大小我没仔细算，但是应该至少有 0x820。本题可被 UAF 的对象大小可能范围为 0x68 ~ 0x818 ，所以用 nft_rule 可以占位到这个范围的所有 cache 中，非常好用。另外，实际上 0x818 还远远不是 nft_rule 可以适用的上限，在后来会提到 nft_rule_dp 结构体，在面对更大的 cache 的 UAF 时，可以用 nft_rule_dp 结构体来辅助利用。这两个结构体非常强大，所有 GFP_KERNEL_ACCOUNT ，size 大于 32 的 cache 中的 UAF ，都可以尝试进行辅助利用。唯一的缺点是由于是 nftables 子系统中的结构体，需要有 CAP_NET_ADMIN 权限才可以使用。（事实上，在 net 子系统中还存在许多非常好用的结构体，比如 nftables 的 nft_table 结构体的 [udata 字段](https://elixir.bootlin.com/linux/v6.6/source/include/net/netfilter/nf_tables.h#L1223)。就可以辅助 leaking）。

有了好用的结构体，利用就只是体力活了：）。利用的总体思路分两步：

1. leak
2. rop 提权

~~内核利用比把大象塞到冰箱里面还简单~~

leak 就是通过 UAF 修改 nft_byteorder expr 的 [sreg](https://elixir.bootlin.com/linux/v6.6/source/net/netfilter/nft_byteorder.c#L19) 字段。由于 [nft_byteorder_eval](https://elixir.bootlin.com/linux/v6.6/source/net/netfilter/nft_byteorder.c#L31) 在拷贝数据时，源地址是通过 `regs->data[priv->sreg]` 获得的。而 regs 结构体就是 [nft_do_chain](https://elixir.bootlin.com/linux/v6.6/source/net/netfilter/nf_tables_core.c#L253) 函数传入的，是 nft_do_chain 函数的一个局部变量，因此，修改 sreg 就可以在栈上任意读（同样的，修改 dreg 就可以在栈上任意写了）。既然可以在栈上任意读，那自然可以通过函数返回地址来进行内核基地址的 leak。本题为了降低难度将 nftables 模块直接编译到了内核当中（kconfig 中 CONFIG_NF_TABLES=y），所以只要 leak 一次就可以了。，一般的发行版会设置为 CONFIG_NF_TABLES=m，这样 nftables 会以模块形式加载到内核，这种情况下可能需要 leak 两次，将 nftables 模块的基地址和内核的基地址都 leak 出来。

在执行完 nft_byteorder_eval 后，nft 的 regs 中就存储了内核代码段地址了，这里我选择使用 nft_payload expr 将 regs 中的数据写到数据包中返回给用户态。

leak 之后就可以进行 rop 了，这里我采用了[这篇文章](https://www.synacktiv.com/publications/old-bug-shallow-bug-exploiting-ubuntu-at-pwn2own-vancouver-2023)提到的方法，伪造 fake nft_payload expr 来修改栈，实现 rop 。

我在利用时 UAF 修改的是 nft_rule 结构体，修改之后进行 dump 操作就可以读出所有的 nft_rule ，借此可以判断是否 UAF 成功。但是要注意的是，实际上在执行 nft_do_chain 时并不会使用 nft_rule ，而是 nft_rule_dp 结构体

```c
do_chain:
	if (genbit)
		blob = rcu_dereference(chain->blob_gen_1);
	else
		blob = rcu_dereference(chain->blob_gen_0);

	rule = (struct nft_rule_dp *)blob->data;
next_rule:
	regs.verdict.code = NFT_CONTINUE;
	for (; !rule->is_last ; rule = nft_rule_next(rule)) {
        // exec the rules..
```

这个 nft_rule_dp 其实是把一个 chain 上所有的 rules 拼接而成的结构体。在我们完成一次 rule 的 add 的操作时，最后会调用 nf_tables_commit 函数，这里面会调用到 [nf_tables_commit_chain_prepare](https://elixir.bootlin.com/linux/v6.6/source/net/netfilter/nf_tables_api.c#L9283) 这个函数，该函数会把 chain 上所有的 nft_rule 都拼接到一个 nft_rule_dp 中（这样 nft_rule_dp 的大小就可以非常巨大）。不过由于 nft_rule_dp 的存在，在完成了对 nft_rule 的 UAF corruption 后，还需要再在对应的 chain 上 add 一次 rule ，将被 currpot 的 nft_rule commit 到 chain 中。

另外建议使用 libmnl + libnftnl 库与 nftbales 进行交互，因为手写 netlink 包真的非常无敌痛苦。

exp 请见 [github 仓库](https://github.com/chujDK/n1ctf2023-n1sub/blob/master/exp/exp.c)

另外在比赛中很多大佬用非预期秒了此题，大家都太强了。除了经典的 pipe 原语之外，[影二つ](https://kagehutatsu.com/?p=909)大佬还使用 USMA 的方法解了此题，非常的牛X。
