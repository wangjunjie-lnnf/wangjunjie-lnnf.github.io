---
layout: post
title:  "性能优化之systemtap"
date:   2023-01-29 10:22:07 +0000
categories: jekyll
tags: perf systemtap
---

# systemtap

[systemtap](https://sourceware.org/systemtap/)
用于收集信息以解决性能或功能问题，提供简单的命令行接口和脚本语言，简化收集信息的过程

## 环境设置

### 编译支持dtrace的jdk

编译jdk之前安装`systemtap和systemtap-sdt-dev`
编译jdk时make命令添加参数`make ALT_SDT_H=/path/to/sys/sdt.h ...`

### 示例java代码

每10秒调用一次`print`，`print`随机延迟一段时间
这段代码模拟一个场景：某段代码性能有问题，忽快忽慢，是否跟输入的参数有关系呢？
很明显，`print`的参数并没有记录到log里。

```java

public class MainApp {

    public static int print(int i) {
        try {
            Thread.sleep(new Random().nextInt(1000));
        } catch (InterruptedException e) {
        }
        System.out.println("count: " + i);
        return i;
    }

    public static void main(String[] args) {
        int i = 0;

        while (true) {
            print(i++);
            try {
                Thread.sleep(10 * 1000);
            } catch (InterruptedException e) {
            }
        }
    }

}

```

编译完之后执行jar

`/path/to/jdk/bin/java -XX:+ExtendedDTraceProbes -cp /path/to/demo.jar com.w.test.MainApp`

jvm默认只启用了一部分dtrace点，`-XX:+ExtendedDTraceProbes`参数可以启用更多的dtrace点，包含本次要用到的`method__entry`

### 实现

目标是获取`print`方法的参数及其耗时信息
systemtap支持自定义脚本以支持复杂的任务

jvm.stp

```c

#! /usr/bin/env stap

global times

probe begin {
  printf("begin3\n")
}

probe process("/path/to/jdk/bin/java").library("/path/to/jdk/lib/aarch64/server/libjvm.so").provider("hotspot").mark("method__entry") {
  class = user_string_n($arg2, $arg3);
  method = user_string_n($arg4, $arg5);
  sign = user_string_n($arg6, $arg7);

  if (class != "com/w/test/MainApp")
    next;

  method_id = sprintf("%s.%s(%s)", class, method, sign);
  times[tid(), method_id] = ktime_get_ns();
  printf("%s entry\n", method_id);
}

probe process("/path/to/jdk/bin/java").library("/path/to/jdk/lib/aarch64/server/libjvm.so").provider("hotspot").mark("method__return") {
  class = user_string_n($arg2, $arg3);
  method = user_string_n($arg4, $arg5);
  sign = user_string_n($arg6, $arg7);

  if (class != "com/w/test/MainApp")
    next;
  
  method_id = sprintf("%s.%s(%s)", class, method, sign);
  delta = ktime_get_ns() - times[tid(), method_id];
  delete times[tid(), method_id]
  printf("%s cost %d \n", method_id, delta / 1000000);
}

probe end {
  printf("end3\n")
}

```

运行脚本 `sudo stap /path/to/jvm.stp`输出以下信息

```shell
begin3
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 410 
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 93 
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 610 
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 890 
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 210 
com/w/test/MainApp.print((I)I) entry
com/w/test/MainApp.print((I)I) cost 933 
```

可以借此实现功能强大的性能分析工具

---

### 遗留问题

单纯的依靠`systemtap`无法获取java方法的参数信息，有一种思路是获取上下文信息遍历栈帧结构

`aarch64`架构下`jvm2.stp`

```c

#! /usr/bin/env stap

global times

probe begin {
  printf("begin3\n")
}

// 嵌入c代码生成此函数，c代码可以访问context
// static void function___global_print_probe_point__overload_0(struct context* __restrict__ c) {
//   {  
//     _stp_printf("====%d %d====\n", c->uregs->sp, c->uregs->pc);
//   }
// }
function print_probe_point() %{
  // -Xint模式下x24指向方法参数
  unsigned long value[33];
  
  // 根据uregs和jvm栈结构遍历栈帧
  struct pt_regs *regs;
	if (CONTEXT->sregs)
	  regs = CONTEXT->sregs;
	else
	  regs = (CONTEXT->user_mode_p ? CONTEXT->uregs : CONTEXT->kregs);

  memcpy(value, ((char *)regs), 264);
  _stp_printf("x0 = 0x%llx\n", value[0]);
  _stp_printf("x1 = 0x%llx\n", value[1]);
  _stp_printf("fp = 0x%llx\n", value[29]);
  _stp_printf("lr = 0x%llx\n", value[30]);
  _stp_printf("sp = 0x%llx\n", value[31]);
  _stp_printf("pc = 0x%llx\n", value[32]);
%}

probe process("/path/to/jdk/bin/java").library("/path/to/jdk/lib/aarch64/server/libjvm.so").provider("hotspot").mark("method__entry") {
  class = user_string_n($arg2, $arg3);
  method = user_string_n($arg4, $arg5);
  sign = user_string_n($arg6, $arg7);

  if (class != "com/w/test/MainApp")
    next;

  method_id = sprintf("%s.%s(%s)", class, method, sign);
  times[tid(), method_id] = ktime_get_ns();
  printf("%s entry\n", method_id);

  printf("x0 = 0x%x\n", u_register("x0"));
  printf("x1 = 0x%x\n", u_register("x1"));
  printf("x29 = 0x%x\n", u_register("x29"));
  printf("x30 = 0x%x\n", u_register("x30"));
  printf("sp = 0x%x\n", u_register("sp"));
  printf("pc = 0x%x\n", u_register("pc"));

  printf("-------------------------------\n")

  print_probe_point();
}

probe process("/path/to/jdk/bin/java").library("/path/to/jdk/lib/aarch64/server/libjvm.so").provider("hotspot").mark("method__return") {
  class = user_string_n($arg2, $arg3);
  method = user_string_n($arg4, $arg5);
  sign = user_string_n($arg6, $arg7);

  if (class != "com/w/test/MainApp")
    next;
  
  method_id = sprintf("%s.%s(%s)", class, method, sign);
  delta = ktime_get_ns() - times[tid(), method_id];
  delete times[tid(), method_id]
  printf("%s cost %d \n", method_id, delta / 1000000);
}

probe end {
  printf("end3\n")
}

```

`systemtap`支持嵌入c代码以实现更复杂的自定义逻辑，运行时加`-g`参数输出以下信息

`v4.8`版本加`-g`参数会报错`Invalid module format`，需要注释掉`buildrun.cxx`的以下代码
```c
if (s.guru_mode)
    make_cmd.push_back("CONFIG_MODVERSIONS=");
```

重新编译之后运行，打印以下信息

```shell

begin3
com/w/test/MainApp.print((I)I) entry
x0 = 0x4
x1 = 0xd6b05d38
x29 = 0xffff7f99dbb0
x30 = 0xffff805e1f60
sp = 0xffff7f99dbb0
pc = 0xffff805e1f60
-------------------------------
x0 = 0x4
x1 = 0xd6b05d38
fp = 0xffff7f99dbb0
lr = 0xffff805e1f60
sp = 0xffff7f99dbb0
pc = 0xffff805e1f60
com/w/test/MainApp.print((I)I) cost 577 

```


结合[jvm解释器](/jekyll/2023/01/28/jvm解释器.html)的栈帧结构遍历栈帧,
理论上是可以获取方法参数的，但是栈帧里存储的都是java对象，通过c解析出有用的信息还是很难的

`systemtap`支持另外一种方式获取java方法参数，借助[byteman](/jekyll/2022/12/04/java应用的可观测性.html)

实现机制是构造一个支持`dtrace`的动态链接库`libHelperSDT.so`

```c

JNIEXPORT void JNICALL Java_org_systemtap_byteman_helper_HelperSDT_METHOD_1STAP_1PROBE0(JNIEnv *, jobject, jstring);
JNIEXPORT void JNICALL Java_org_systemtap_byteman_helper_HelperSDT_METHOD_1STAP_1PROBE1(JNIEnv *, jobject, jstring, jobject)
{
  int64_t sargs[1];
  _Bool sfree[1];
  jobject jargs[1] = {_arg1};
  // 判断参数类型，基本类型保持不变，对象类型调用.toString()转换为字符串
  char *rulename = alloc_sargs(sargs, sfree, env, obj, _rulename, jargs, 1);
  // dtrace点
  STAP_PROBE2(HelperSDT, method__1, sargs[0], rulename);
  free_sargs(rulename, sargs, sfree, 1);
}

...

// 最多支持10个参数
JNIEXPORT void JNICALL Java_org_systemtap_byteman_helper_HelperSDT_METHOD_1STAP_1PROBE10(JNIEnv *, jobject, jstring, jobject, jobject, jobject, jobject, jobject, jobject, jobject, jobject, jobject, jobject);

```

还有一个配套的java类

```java

public class HelperSDT<T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>
{
    public void STAP_BACKTRACE(String rulename){
        Throwable e = new Throwable();
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String exceptionAsString = sw.toString();
        String[] stackline = exceptionAsString.split("\n");
        int __counter = 0;
        for(String result : stackline){
            METHOD_STAP_BT(rulename, result, __counter);
            __counter++;
        }
    }
    public native void METHOD_STAP_PROBE0(String rulename);
    public native void METHOD_STAP_PROBE1(String rulename, T2 arg1);
    public native void METHOD_STAP_PROBE2(String rulename, T2 arg1, T3 arg2);
    public native void METHOD_STAP_PROBE3(String rulename, T2 arg1, T3 arg2, T4 arg3);
    public native void METHOD_STAP_PROBE4(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4);
    public native void METHOD_STAP_PROBE5(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5);
    public native void METHOD_STAP_PROBE6(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5, T7 arg6);
    public native void METHOD_STAP_PROBE7(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5, T7 arg6, T8 arg7);
    public native void METHOD_STAP_PROBE8(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5, T7 arg6, T8 arg7, T9 arg8);
    public native void METHOD_STAP_PROBE9(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5, T7 arg6, T8 arg7, T9 arg8, T10 arg9);
    public native void METHOD_STAP_PROBE10(String rulename, T2 arg1, T3 arg2, T4 arg3, T5 arg4, T6 arg5, T7 arg6, T8 arg7, T9 arg8, T10 arg9, T11 arg10);
    public native void METHOD_STAP_BT(String rulename, String exceptionAsString, int __counter);
    public native void METHOD_BT_DELETE(String rulename);
    static{
        System.load("/home/w/systemtap/libexec/systemtap/libHelperSDT.so");
    }
}

```

对应的`byteman`脚本，修改指定类的指定方法的字节码，增加对`HelperSDT.METHOD_STAP_PROBEx`的调用

```shell

function echo_bytemanrule()
{
    echo "RULE $arg_rulename"
    echo "CLASS $arg_class"
    echo "METHOD $arg_method"
    echo "HELPER org.systemtap.byteman.helper.HelperSDT"
    case "$arg_probetype" in
        entry)
	    echo "AT ENTRY"
	    ;;
        exi*)
	    echo "AT RETURN"
	    ;;
        *)
	    echo "AT LINE $arg_probetype"
	    ;;
    esac
    echo "IF TRUE"
    if [ "$arg_backtrace" == "1" ]; then
	echo 'DO STAP_BACKTRACE("'$arg_rulename'");'
    else
	echo -n 'DO '
    fi
    case "$arg_argcount" in
        # For PR21010, we invoke another java<->stap ABI
        0) echo -n 'METHOD_STAP'$stap'_PROBE0("'$arg_rulename'")' ;;
        1) echo -n 'METHOD_STAP'$stap'_PROBE1("'$arg_rulename'", $1)' ;;
        2) echo -n 'METHOD_STAP'$stap'_PROBE2("'$arg_rulename'", $1, $2)' ;;
        3) echo -n 'METHOD_STAP'$stap'_PROBE3("'$arg_rulename'", $1, $2, $3)' ;;
        4) echo -n 'METHOD_STAP'$stap'_PROBE4("'$arg_rulename'", $1, $2, $3, $4)' ;;
        5) echo -n 'METHOD_STAP'$stap'_PROBE5("'$arg_rulename'", $1, $2, $3, $4, $5)' ;;
        6) echo -n 'METHOD_STAP'$stap'_PROBE6("'$arg_rulename'", $1, $2, $3, $4, $5, $6)' ;;
        7) echo -n 'METHOD_STAP'$stap'_PROBE7("'$arg_rulename'", $1, $2, $3, $4, $5, $6, $7)' ;;
        8) echo -n 'METHOD_STAP'$stap'_PROBE8("'$arg_rulename'", $1, $2, $3, $4, $5, $6, $7, $8)' ;;
        9) echo -n 'METHOD_STAP'$stap'_PROBE9("'$arg_rulename'", $1, $2, $3, $4, $5, $6, $7, $8, $9)' ;;
	10) echo -n 'METHOD_STAP'$stap'_PROBE10("'$arg_rulename'", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)' ;;
        *) echo 'bad arg-count'; exit 1 ;;
    esac
    if [ "$arg_backtrace" == "1" ]; then
	echo ';'
	echo 'METHOD_BT_DELETE("'$arg_rulename'")'
    else
	echo ''
    fi
    echo "ENDRULE"
}

```

然后修改`jvm.stp`中的`probe`点即可获取方法参数

只使用byteman就可实现的功能为什么还要绕个弯？一旦转换成dtrace，就会打开另一个广阔天地的大门：`bpf`

---

## systemtap实现机制

![systemtap处理流程](/assets/images/2023-01-29/systemtap.png)

### 解析脚本生成c文件

在`translate.cxx`的`delete s.op;`这一行打断点，就可以从`s.op`中看到c文件的路径

### 编译成内核模块

生成的c文件需要跟`runtime`一起编译链接成内核模块

### 执行

通过`inmod/rmmod`加载/卸载内核模块，获取输出信息

![stap代码流程](/assets/images/2023-01-29/stap-code.png)

`{src_root}/runtime/linux/runtime.h`包含内核模块的入口

```c

// 这俩函数定义在根据stp脚本动态生成的c文件里
static int systemtap_kernel_module_init(void);
static void systemtap_kernel_module_exit(void);

// 内核模块入口
int init_module(void)
{
  int rc;
  rc = systemtap_kernel_module_init();
  if (rc)
    return rc;
  // 核心流程
  rc = _stp_transport_init();
  {
    // 在debugfs/procfs中注册.cmd文件接收指令
    if (debugfs_p)
        return _stp_debugfs_register_ctl_channel_fs();
    if (procfs_p)
        return _stp_procfs_register_ctl_channel_fs();
    。。。

    // 由于历史原因向stapio发送STP_TRANSPORT命令
    // 之后stapio会再发送STP_START命令
    _stp_ctl_send_notify(STP_TRANSPORT, NULL, 0);
  }
  if (rc)
    systemtap_kernel_module_exit();
  return rc;
}

// 内核模块出口
void cleanup_module(void)
{
  _stp_transport_close();
  systemtap_kernel_module_exit();
}

```

`{src_root}/runtime/transport/control.c`处理`.cmd`文件的读写事件

```c

// 向.cmd文件写入命令的handler
static ssize_t _stp_ctl_write_cmd(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    ...
    // 获取命令类型
    u32 type;
    if (get_user(type, (u32 __user *)buf))
		return -EFAULT;
    ...

    switch (type)
	{
	case STP_START:
	{
        // start命令由stapio程序发起，参数包含pid
		static struct _stp_msg_start st;
		if (copy_from_user(&st, buf, sizeof(st)))
		{
			rc = -EFAULT;
			goto out;
		}
		
		_stp_handle_start(&st);
        {
            ...
            // systemtap_module_init定义在生成的c文件里
            st->res = systemtap_module_init();
            {
                ...
                // 创建context
                rc = _stp_runtime_contexts_alloc();
                
                // 定时调用api注册uprobe: 解决启动顺序问题，systemstap可以先于应用启动
                INIT_WORK(&module_refresher_work, module_refresher);
                {
                    systemtap_module_refresh(NULL);
                    {
                        // stap_inode_uprobe_consumers定义在动态生成的c文件里
                        stapiu_refresh(stap_inode_uprobe_consumers, ARRAY_SIZE(stap_inode_uprobe_consumers));
                        {
                            ...
                            stapiu_consumer_refresh(c);
                            {
                                inst->kconsumer.handler = stapiu_probe_prehandler;
                                uprobe_register(inst->inode, c->offset, &inst->kconsumer);
                            }
                            ...
                        }
                    }
                }
            }
            ...
        }
	}
    ...
    }
    ...
}

```

`{src_root}/runtime/linux/uprobes-inode.c`

```c
// uprobe事件发生时由内核调用
static int stapiu_probe_prehandler(struct uprobe_consumer *inst, struct pt_regs *regs) {

    struct stapiu_instance *instance = container_of(inst, struct stapiu_instance, kconsumer);
    struct stapiu_consumer *c = instance->sconsumer;

    unsigned long saved_ip = REG_IP(regs);
    SET_REG_IP(regs, uprobe_get_swbp_addr(regs));

    // stapiu_probe_handler定义在生成的c文件里，执行业务逻辑
    ret = stapiu_probe_handler(c, regs);

    SET_REG_IP(regs, saved_ip);

}

```

生成的c代码在uprobe事件触发后开始执行

```c

static int stapiu_probe_handler(struct stapiu_consumer *sup, struct pt_regs *regs) {
    ...
    c->uregs = regs;
    c->user_mode_p = 1;
    // 执行用户定义的handler
    (*sup->probe->ph)(c);
    ...
}

static void probe_6232(struct context *__restrict__ c) {
    ...
    // 解析class，它怎么知道class字符串的地址和长度保存在寄存器x20和x21呢，往下看
    (void)({
      ({
        l->__tmp2 = (((int64_t)(/* unprivileged */ /* pure */ ((int64_t)(uint64_t)((u_fetch_register(20)))))));
        l->__tmp3 = (((int64_t)(/* unprivileged */ /* pure */ ((int64_t)(int32_t)((u_fetch_register(21)))))));
        c->locals[c->nesting + 1].function___global_user_string_n__overload_0.l_addr = l->__tmp2;
        c->locals[c->nesting + 1].function___global_user_string_n__overload_0.l_n = l->__tmp3;
        c->locals[c->nesting + 1].function___global_user_string_n__overload_0.__retvalue = &l->__tmp0[0];
        c->last_stmt = "identifier 'user_string_n' at docs/examples/jvm/jvm.stp:18:11";
        function___global_user_string_n__overload_0(c);
        if (unlikely(c->last_error || c->aborted))
          goto out;
        (void)0;
      });
      strlcpy(l->l_class, l->__tmp0, MAXSTRINGLEN);
      l->__tmp0;
    });
    ...
}

```

[dtrace](/jekyll/2023/02/06/性能优化之usdt.html)会把位点和参数信息写入elf文件的.note段

`readelf -n /path/to/libjvm.so`

```

...

Provider: hotspot
Name: method__entry
Location: 0x0000000000ba1f60, Base: 0x0000000001094368, Semaphore: 0x0000000000000000
Arguments: -8@x19 8@x20 -4@x21 8@x22 -4@x23 8@x24 -4@x0

...

```

Location和Base指定了text段的位置，此处默认是一条nop指令，开始dtrace时会替换为brk指令  
Arguments指定了trace时每个参数的位置











