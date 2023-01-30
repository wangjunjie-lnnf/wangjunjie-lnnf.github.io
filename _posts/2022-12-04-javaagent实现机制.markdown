---
layout: post
title:  "javaagent实现机制"
date:   2022-12-04 02:56:07 +0800
categories: java
tags: java javaagent
---

# javaagent实现机制

## jvmti

TheJVM Tool Interface (JVM TI) is a programming interface used by development and monitoring tools. It provides both a way to inspect the state and to control the execution of applications running in the Java VirtualMachine (VM). JVM TI is a two-way interface. A client of JVM TI, hereafter called an agent, can be notified of interesting occurrences through events. 

JVM TI can query and control the application through many functions, either in response to events or independent of them. Agents run in the same process with and communicate directly with the virtual machine executing the application being examined. This communication is through a native interface (JVM TI). The native in-process interface allows maximal control with minimal intrusion on the part of a tool. Typically, agents are relatively compact. They can be controlled by a separate process which implements the bulk of a tool's function without interfering with the target application's normal execution.

来源：https://docs.oracle.com/javase/8/docs/platform/jvmti/jvmti.html#whatIs

![jvm-load-agent](/assets/images/2022-12-04/jvm-load-agent.jpg)

jvmti是一个双向接口，参与者是agent和jvm，agent运行在jvm进程内。

1. agent通过jvmti可以获取应用的状态，控制应用的行为。  

jvm加载agent时会调用其Agent_OnLoad方法

```c++

// Agent_OnLoad
jint (JNICALL *OnLoadEntry_t)(JavaVM *, char *, void *)

// JavaVM
struct JavaVM_ {
    const struct JNIInvokeInterface_ *functions;
    ...
};

struct JNIInvokeInterface_ {
    ...
    jint (JNICALL *DestroyJavaVM)(JavaVM *vm);
    jint (JNICALL *AttachCurrentThread)(JavaVM *vm, void **penv, void *args);
    jint (JNICALL *DetachCurrentThread)(JavaVM *vm);
    // 创建jvmtiEnv
    jint (JNICALL *GetEnv)(JavaVM *vm, void **penv, jint version);
    jint (JNICALL *AttachCurrentThreadAsDaemon)(JavaVM *vm, void **penv, void *args);
};

```

agent在获取`JavaVM`引用之后可以通过`vm->functions->GetEnv(...)`创建`jvmtiEnv`。

```c++

struct _jvmtiEnv {
    const struct jvmtiInterface_1_ *functions;
    ...
}

// 省略大量的查询状态和控制行为的接口
typedef struct jvmtiInterface_1_ {
  ...
  /*   78 : Get Loaded Classes */
  jvmtiError (JNICALL *GetLoadedClasses) (jvmtiEnv* env, 
    jint* class_count_ptr, 
    jclass** classes_ptr);
  ...
  /*   122 : Set Event Callbacks */
  jvmtiError (JNICALL *SetEventCallbacks) (jvmtiEnv* env, 
    const jvmtiEventCallbacks* callbacks, 
    jint size_of_callbacks);
  ...
  /*   132 : Set System Property */
  jvmtiError (JNICALL *SetSystemProperty) (jvmtiEnv* env, 
    const char* property, 
    const char* value_ptr);
  ...
}

```

2. jvm通过发布event通知agent做出响应

agent在初始化时可以通过`jvmtiEnv->functions->SetEventCallbacks(...)`注册感兴趣的事件。

```c++
 
 // 省略大量无关内容
 typedef struct {
    jvmtiEventVMInit VMInit;
    ...
    jvmtiEventClassFileLoadHook ClassFileLoadHook;
    ...
} jvmtiEventCallbacks;


```

## javaagent运行机制

javaagent的实现基于jvm内置的`jvmti` agent `libinstrument.so`。

```c++

// Arguments.cpp
if (match_option(option, "-javaagent:", &tail)) {
  if(tail != NULL) {
    size_t length = strlen(tail) + 1;
    char *options = NEW_C_HEAP_ARRAY(char, length, mtInternal);
    jio_snprintf(options, length, "%s", tail);
    add_init_agent("instrument", options, false);
  }
}

```

1. 启动时加载

jvm在启动过程中会调用所有agent的`Agent_OnLoad`方法，`libinstrument.so`在被调用时jvm尚未初始化完成，此时无法调用javaagent的`premain`方法使其初始化，所以初始化分成两个阶段，第一阶段`libinstrument.so`会通过`jvmtiEnv`注册`VMInit`事件等待jvm初始化完成，jvm初始化完成后开始第二阶段的初始化

```c++

// libinstrument.so
jint JNICALL Agent_OnLoad(JavaVM *vm, char *tail, void * reserved) {
  // 创建jvmtiEnv
  createNewJPLISAgent(vm, &agent);
  // 注册VMInit事件
  jvmtiEventCallbacks callbacks;
  callbacks.VMInit = &eventHandlerVMInit;
  jvmtierror = (*jvmtienv)->SetEventCallbacks(jvmtienv, &callbacks, sizeof(callbacks));
  // 解析javaagent的manifest获取Premain-Class属性
  readAttributes(jarfile);
  // Add the jarfile to the system class path
  appendClassPath(agent, jarfile);
  // 加入bootclasspath
  bootClassPath = getAttribute(attributes, "Boot-Class-Path");
  if (bootClassPath != NULL) {
      appendBootClassPath(agent, jarfile, bootClassPath);
  }
  // 处理manifest中的其他属性: Can-Redefine-Classes, Can-Retransform-Classes
  convertCapabilityAtrributes(attributes, agent);
}

```

在jvm初始化完成后会发布`VMInit`事件

```c++

// threads.cpp
JvmtiExport::post_vm_initialized();

```

`libinstrument.so`在收到`VMInit`事件后完成剩余的初始化

```c++

// 创建java.lang.instrument.Instrumentation的实现类
createInstrumentationImpl(jnienv, agent);
// 注册ClassFileLoadHook：每次加载字节码时都会触发此事件
callbacks.ClassFileLoadHook = &eventHandlerClassFileLoadHook;
jvmtierror = (*jvmtienv)->SetEventCallbacks(jvmtienv, &callbacks, sizeof(callbacks));
// 调用javaagent的premain方法
startJavaAgent(agent, jnienv,
               agent->mAgentClassName, agent->mOptionsString,
               agent->mPremainCaller)

```

2. 运行时attach

![jvm-attach-agent](/assets/images/2022-12-04/jvm-attach-agent.png)

* attach client  

jdk中实现`client`的接口是`tools.jar`中的类`com.sun.tools.attach.VirtualMachine`

触发jvm启动`AttachListener`的条件是，先以启动此jvm的用户的身份创建`/tmp/.attach_pid{目标jvm的pid}`，然后用`kill -3 $pid`发送signal

```java

public class VirtualMachine {
  ...
  // attach到指定pid的jvm
  public static VirtualMachine attach(String pid) {
    // 通过spi加载AttachProvider
    ServiceLoader<AttachProvider> providerLoader =
                    ServiceLoader.load(AttachProvider.class,
                                       AttachProvider.class.getClassLoader());

    Iterator<AttachProvider> i = providerLoader.iterator();
    while (i.hasNext()) {
        try {
            AttachProvider provider = i.next();
            return provider.attachVirtualMachine(id);
        } catch (AttachNotSupportedException x) {
            lastExc = x;
        }
    }
  }
  // 动态加载javaagent: 发送load指令给AttachListener
  public abstract void loadAgent(String agent, String options);
  ...
}

public class LinuxAttachProvider extends HotSpotAttachProvider {

    public VirtualMachine attachVirtualMachine(String vmid)
    {
        return new LinuxVirtualMachine(this, vmid);
    }

}

public class LinuxVirtualMachine extends HotSpotVirtualMachine {


  LinuxVirtualMachine(AttachProvider provider, String vmid) {

    int pid = Integer.parseInt(vmid);
    
    // 检查/tmp/.java_pidxxx判断AttachListener是否已启动
    File f = new File(tmpdir, ".java_pid" + pid);
    String path = f.getPath();
    if (path == null) {
        // 在cwd下创建.attach_pidxxx文件
        String fn = ".attach_pid" + pid;
        File f = new File("/proc/" + pid + "/cwd/" + fn);
        f.createNewFile();

        try {
          // 发送signal通知AttachListener启动
          if (isLinuxThreads) {
              int mpid = getLinuxThreadsManager(pid);
              sendQuitToChildrenOf(mpid);
          } else {
              sendQuitTo(pid);
          }

          // 循环检查AttachListener是否启动成果
          int i = 0;
          long delay = 200;
          int retries = (int)(attachTimeout() / delay);
          do {
              try {
                  Thread.sleep(delay);
              } catch (InterruptedException x) { }
              path = findSocketFile(pid);
              i++;
          } while (i <= retries && path == null);

          if (path == null) {
              throw new AttachNotSupportedException("xxx");
          }
        } finally {
            f.delete();
        }
    }
  }

}

```

* attach server  

`server`端功能的实现依赖`AttachListener`，`AttachListener`在jvm启动时默认不会初始化，只有在收到`signal SIGBREAK(kill -3 $pid)`时才开始初始化

```c++

// 先检查当前目录下.attach_pidxxx是否存在
char fn[PATH_MAX+1];
sprintf(fn, ".attach_pid%d", os::current_process_id());
int ret;
struct stat64 st;
RESTARTABLE(::stat64(fn, &st), ret);
if (ret == -1) {
  // 再检查/tmp/.attach_pidxxx是否存在
  snprintf(fn, sizeof(fn), "%s/.attach_pid%d",
           os::get_temp_directory(), os::current_process_id());
  RESTARTABLE(::stat64(fn, &st), ret);
}
if (ret == 0) {
  // 检查创建.attach_pid文件的用户是否是启动jvm的用户
  if (st.st_uid == geteuid()) {
    // 开始初始化
    init();
    return true;
  }
}

```

`AttachListener`启动时会建立unix sock

```c++

snprintf(path, UNIX_PATH_MAX, "%s/.java_pid%d",
         os::get_temp_directory(), os::current_process_id());

snprintf(initial_path, UNIX_PATH_MAX, "%s.tmp", path);
  
// create the listener socket
listener = ::socket(PF_UNIX, SOCK_STREAM, 0);

// bind socket
struct sockaddr_un addr;
addr.sun_family = AF_UNIX;
strcpy(addr.sun_path, initial_path);
::unlink(initial_path);
::bind(listener, (struct sockaddr*)&addr, sizeof(addr));

// put in listen mode, set permissions, and rename into place
::listen(listener, 5);
::chmod(initial_path, S_IREAD|S_IWRITE);
::rename(initial_path, path);

```

然后等待接收指令，支持的指令列表

```c++

static AttachOperationFunctionInfo funcs[] = {
  { "agentProperties",  get_agent_properties },
  { "datadump",         data_dump },
  { "dumpheap",         dump_heap },
  { "load",             JvmtiExport::load_agent_library },
  { "properties",       get_system_properties },
  { "threaddump",       thread_dump },
  { "inspectheap",      heap_inspection },
  { "setflag",          set_flag },
  { "printflag",        print_flag },
  { "jcmd",             jcmd },
  { NULL,               NULL }
};

```

`AttachListener`收到`load`指令后会调用`libinstrument.so`的`Agent_OnAttach`函数

```c++

jint (JNICALL *OnAttachEntry_t)(JavaVM*, char *, void *);

```

`Agent_OnAttach`的初始化流程

```c++

// 创建jvmtiEnv
createNewJPLISAgent(vm, &agent);
// 解析jar的manifest
readAttributes(jarfile);
// 解析javaagent的manifest获取Agent-Class属性
getAttribute(attributes, "Agent-Class");
// Add the jarfile to the system class path
appendClassPath(agent, jarfile);
// 加入bootclasspath
bootClassPath = getAttribute(attributes, "Boot-Class-Path");
if (bootClassPath != NULL) {
    appendBootClassPath(agent, jarfile, bootClassPath);
}
// 处理manifest中的其他属性: Can-Redefine-Classes, Can-Retransform-Classes
convertCapabilityAtrributes(attributes, agent);
// 创建java.lang.instrument.Instrumentation的实现类
createInstrumentationImpl(jnienv, agent);
// 注册ClassFileLoadHook：每次加载字节码时都会触发此事件
callbacks.ClassFileLoadHook = &eventHandlerClassFileLoadHook;
jvmtierror = (*jvmtienv)->SetEventCallbacks(jvmtienv, &callbacks, sizeof(callbacks));
// 调用javaagent的agentmain方法
startJavaAgent(agent, jnienv,
               agentClass, options,
               agent->mAgentmainCaller)

```

## javaagent初始化

![class-transformer](/assets/images/2022-12-04/class-transformer.png)

```java

// 动态attach的入口
public static void agentmain(String args, Instrumentation inst) throws Exception;
// 启动时加载的入口: 先于main方法执行
public static void premain(String args, Instrumentation inst) throws Exception

```

与jvm交互的接口是类`java.lang.instrument.Instrumentation`

```java

public interface Instrumentation {
  void addTransformer(ClassFileTransformer transformer, boolean canRetransform);
  // 取决于jar的manifest是否设置了Can-Redefine-Classes
  boolean isRetransformClassesSupported();
  void retransformClasses(Class<?>... classes);
  // 取决于jar的manifest是否设置了Can-Retransform-Classes
  boolean isRedefineClassesSupported();
  void redefineClasses(ClassDefinition... definitions);
  ...
}

```

`retransformClasses`和`redefineClasses`的注释明确说明了他们的行为和限制

> If a redefined/retransformed method has active stack frames, those active frames continue to run the bytecodes of the original method. The redefined/retransformed method will be used on new invokes.

<font color=red>修改了方法体的字节码之后不影响现存的栈帧</font>

> This method does not cause any initialization except that which would occur under the customary JVM semantics. In other words, redefining a class does not cause its initializers to be run. The values of static variables will remain as they were prior to the call.

<font color=red>redefined/retransformed不会执行其**cinit**，不影响静态变量的值</font>

> Instances of the redefined/retransformed class are not affected.

<font color=red>现存的实例不受影响</font>

> The redefinition/retransformation may change method bodies, the constant pool and attributes. The redefinition/retransformation must not add, remove or rename fields or methods, change the signatures of methods, or change inheritance. These restrictions maybe be lifted in future versions. The class file bytes are not checked, verified and installed until after the transformations have been applied, if the resultant bytes are in error this method will throw an exception.

<font color=red>redefined/retransformed只能修改方法体的字节码，不能增减方法和字段，不能修改方法签名，不能改变继承关系</font>

> If this method throws an exception, no classes have been redefined.

<font color=red>如果转换出错，字节码保持不变</font>


### retransformClasses和redefineClasses实现机制

通过`Instrumentation`来触发字节码的变更

```c++

JvmtiEnv::RedefineClasses(jint class_count, const jvmtiClassDefinition* class_definitions) {
  VM_RedefineClasses op(class_count, class_definitions, jvmti_class_load_kind_redefine);
  VMThread::execute(&op);
  return (op.check_error());
} 

JvmtiEnv::RetransformClasses(jint class_count, const jclass* classes) {
  ...
  VM_RedefineClasses op(class_count, class_definitions, jvmti_class_load_kind_retransform);
  VMThread::execute(&op);
  return (op.check_error());
}

```

两者几乎没有区别，都是通过`VM_RedefineClasses`实现，只是参数不同而已。

```c++

class VM_RedefineClasses {

  bool doit_prologue() {
    ...
    lock_classes();
    // 触发ClassFileLoadHook事件转换字节码
    load_new_class_versions(Thread::current());
    unlock_classes();
    ...
  }
  
  // VM_RedefineClasses的mode是_safepoint, 所以会在safepoint中执行，避免了java线程看到class的中间状态
  void doit() {
    ...
    for (int i = 0; i < _class_count; i++) {
      // 使用最终的字节码修改内存中jclass
      redefine_single_class(_class_defs[i].klass, _scratch_classes[i], thread);
    }
    ...
  }

}

```

jvm发布`ClassFileLoadHook`事件，此事件已被所有`javaagent`订阅

```c++

void post_all_envs() {
  if (_load_kind != jvmti_class_load_kind_retransform) {
    // define和redefine时通知非retransformable的agent
    JvmtiEnvIterator it;
    for (JvmtiEnv* env = it.first(); env != NULL; env = it.next(env)) {
      if (!env->is_retransformable() && env->is_enabled(JVMTI_EVENT_CLASS_FILE_LOAD_HOOK)) {
        post_to_env(env, false);
      }
    }
  }

  // 所有event都通知retransformable的agent
  JvmtiEnvIterator it;
  for (JvmtiEnv* env = it.first(); env != NULL; env = it.next(env)) {
    if (env->is_retransformable() && env->is_enabled(JVMTI_EVENT_CLASS_FILE_LOAD_HOOK)) {
      post_to_env(env, true);
    }
  }
}

void post_to_env(JvmtiEnv* env, bool caching_needed) {
  jvmtiEventClassFileLoadHook callback = env->callbacks()->ClassFileLoadHook;
  if (callback != NULL) {
    (*callback)(env->jvmti_external(), jni_env,
                jem.class_being_redefined(),
                jem.jloader(), jem.class_name(),
                jem.protection_domain(),
                _curr_len, _curr_data,
                &new_len, &new_data);
  }
}

```

`javaagent`在收到event之后调用`InstrumentationImpl#transform(...)`实现字节码转换

```java

// retransform会调用所有支持retransform的javaagent的支持retransform的ClassFileTransformer
// define/redefine会调用所有javaagent的不支持retransform的ClassFileTransformer
private byte[]
    transform(  ClassLoader         loader,
                String              classname,
                Class<?>            classBeingRedefined,
                ProtectionDomain    protectionDomain,
                byte[]              classfileBuffer,
                boolean             isRetransformer) {
        TransformerManager mgr = isRetransformer ?
                                        mRetransfomableTransformerManager :
                                        mTransformerManager;
        if (mgr == null) {
            return null; // no manager, no transform
        } else {
            return mgr.transform(   loader,
                                    classname,
                                    classBeingRedefined,
                                    protectionDomain,
                                    classfileBuffer);
        }
    }

```

实现字节码转换的类是`java.lang.instrument.ClassFileTransformer`

```java

public interface ClassFileTransformer {
  byte[] transform(  ClassLoader         loader,
                     String              className,
                     Class<?>            classBeingRedefined,
                     ProtectionDomain    protectionDomain,
                     byte[]              classfileBuffer)
}

```

`ClassFileTransformer`类的注释详细说明了其使用场景

> Once a transformer has been registered with addTransformer, <font color=red>the transformer will be called for every new class definition and every class redefinition</font>. <font color=red>Retransformation capable transformers will also be called on every class retransformation</font>. The request for a new class definition is made with <font color=red>ClassLoader.defineClass</font> or its native equivalents. The request for a class redefinition is made with <font color=red>Instrumentation.redefineClasses</font> or its native equivalents. The request for a class retransformation is made with <font color=red>Instrumentation.retransformClasses</font> or its native equivalents. The transformer is called during the processing of the request, before the class file bytes have been verified or applied. When there are multiple transformers, <font color=red>transformations are composed by chaining the transform calls</font>. That is, the byte array returned by one call to transform becomes the input (via the classfileBuffer parameter) to the next call.

以上三种场景的区别: 主要区别是初始字节码的来源

| 方式 | 区别 |
| - | - |
| ClassLoader.defineClass	| 初始字节码来源于class文件 |
| Instrumentation.redefineClasses	| 初始字节码由调用方直接提供 |
| Instrumentation.retransformClasses | 初始字节码从内存获取 |


## 总结

javaagent可以在运行时修改字节码，改变应用的行为，是非侵入式实现aop的上上之选



















