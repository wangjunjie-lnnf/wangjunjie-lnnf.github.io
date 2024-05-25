---
layout: post
title:  "llvm: driver"
date:   2024-05-21 20:49:07 +0000
categories: llvm
tags: llvm
---

# driver


## 概述

从源文件和可执行文件是一个很复杂的过程，要经过很多步骤。
执行命令`bin/clang -ccc-print-phases demo/main.c`会打印每个步骤如下：

```shell

w@wjj:~/github/llvm-debug$ build66/bin/clang -ccc-print-phases demo/main.c
            +- 0: input, "demo/main.c", c
         +- 1: preprocessor, {0}, cpp-output
      +- 2: compiler, {1}, ir
   +- 3: backend, {2}, assembler
+- 4: assembler, {3}, object
5: linker, {4}, image

```

从上述输出可以看出一共划分为5个过程：

1. 预处理源文件
2. 编译上一步的输出产生中间代码ir
3. 根据选择的指令集由上一步的中间代码产生汇编代码
4. 汇编上一步的代码产生obj二进制文件
5. 链接上一步的obj文件产生可执行文件

执行命令`bin/clang -fno-integrated-as -### demo/main.c`会打印具体的指令：

```shell

w@wjj:~/github/llvm-debug$ build66/bin/clang -fno-integrated-as -### demo/main.c
clang version 18.1.2 (https://github.com/wangjunjie-lnnf/llvm-debug.git 7029e1073e82a8f63a3ba146445fd7257aa24a54)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /home/w/github/llvm-debug/build66/bin
 "/home/w/github/llvm-debug/build66/bin/clang-18" "-cc1" "-triple" "x86_64-unknown-linux-gnu" "-S" "-dumpdir" "a-" "-disable-free" "-clear-ast-before-backend" "-main-file-name" "main.c" "-mrelocation-model" "pic" "-pic-level" "2" "-pic-is-pie" "-mframe-pointer=all" "-fmath-errno" "-ffp-contract=on" "-fno-rounding-math" "-no-integrated-as" "-mconstructor-aliases" "-funwind-tables=2" "-target-cpu" "x86-64" "-tune-cpu" "generic" "-debugger-tuning=gdb" "-fno-dwarf-directory-asm" "-fdebug-compilation-dir=/home/w/github/llvm-debug" "-fcoverage-compilation-dir=/home/w/github/llvm-debug" "-resource-dir" "/home/w/github/llvm-debug/build66/lib/clang/18" "-internal-isystem" "/home/w/github/llvm-debug/build66/lib/clang/18/include" "-internal-isystem" "/usr/local/include" "-internal-isystem" "/usr/lib/gcc/x86_64-linux-gnu/11/../../../../x86_64-linux-gnu/include" "-internal-externc-isystem" "/usr/include/x86_64-linux-gnu" "-internal-externc-isystem" "/include" "-internal-externc-isystem" "/usr/include" "-ferror-limit" "19" "-fgnuc-version=4.2.1" "-fskip-odr-check-in-gmf" "-fcolor-diagnostics" "-D__GCC_HAVE_DWARF2_CFI_ASM=1" "-o" "/tmp/main-39e31e.s" "-x" "c" "demo/main.c"
 "/usr/bin/as" "--64" "-o" "/tmp/main-f5a38a.o" "/tmp/main-39e31e.s"
 "/usr/bin/ld" "-z" "relro" "--hash-style=gnu" "--eh-frame-hdr" "-m" "elf_x86_64" "-pie" "-dynamic-linker" "/lib64/ld-linux-x86-64.so.2" "-o" "a.out" "/lib/x86_64-linux-gnu/Scrt1.o" "/lib/x86_64-linux-gnu/crti.o" "/usr/lib/gcc/x86_64-linux-gnu/11/crtbeginS.o" "-L/usr/lib/gcc/x86_64-linux-gnu/11" "-L/usr/lib/gcc/x86_64-linux-gnu/11/../../../../lib64" "-L/lib/x86_64-linux-gnu" "-L/lib/../lib64" "-L/usr/lib/x86_64-linux-gnu" "-L/usr/lib/../lib64" "-L/lib" "-L/usr/lib" "/tmp/main-f5a38a.o" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "-lc" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "/usr/lib/gcc/x86_64-linux-gnu/11/crtendS.o" "/lib/x86_64-linux-gnu/crtn.o"

```

从上述输出可以看出执行了3条指令：

1. `bin/clang-18 -cc1 -S main.c ...`: 调用编译器编译源文件产生汇编文件
2. `/usr/bin/as -o xxx.o xxx.s`: 调用系统默认汇编器产生obj文件
3. `/usr/bin/ld -o a.out xxx.o`: 调用系统默认连接器产生可执行文件

之所以叫driver就是因为它会根据输入文件的类型以及各种选项指定的目标类型选择合适的工具完成转换。


## 处理过程

### 主流程

```c++

int clang_main(int Argc, char **Argv, ...) {
    // 注册所有支持的target
    llvm::InitializeAllTargets();

    // 构造driver
    Driver TheDriver(Path, llvm::sys::getDefaultTargetTriple(), ...);

    if (!UseNewCC1Process) {
        // 直接在当前进程执行cc1编译命令，便于调试
        TheDriver.CC1Main = [ToolContext](SmallVectorImpl<const char *> &ArgV) {
            return ExecuteCC1Tool(ArgV, ToolContext);
        };
    }

    // 根据源和目标的类型构造执行计划
    std::unique_ptr<Compilation> C(TheDriver.BuildCompilation(Args));

    // 执行
    TheDriver.ExecuteCompilation(*C, FailingCommands);
}

// 根据源和目标的类型构造执行计划
Compilation *Driver::BuildCompilation(ArrayRef<const char *> ArgList) {
    // 根据参数-target/-m64/-march/-mcpu等计算目标类型
    const llvm::Triple targetTriple = computeTargetTriple(*this, TargetTriple, *UArgs);
    
    // 支持交叉编译
    // 选择工具链：为编译的每个步骤选择要执行的命令
    const ToolChain &TC = getToolChain(*UArgs, targetTriple);

    Compilation *C = new Compilation(*this, TC, ...);

    // 根据每个输入文件的后缀确定其类型
    InputList Inputs;
    BuildInputs(C->getDefaultToolChain(), *TranslatedArgs, Inputs);

    // 根据输入文件类型和目标类型确定执行计划
    BuildActions(*C, C->getArgs(), Inputs, C->getActions());

    // -ccc-print-phases打印phase
    if (CCCPrintPhases) {
        PrintActions(*C);
        return C;
    }

    // 构造执行计划
    BuildJobs(*C);
}

```

### 工具链选择

llvm是支持交叉编译的，所以第一个步骤就是先确定编译目标，编译目标由`Triple`表示。

```c++

class Triple {
public:
    enum ArchType {
        UnknownArch,
        aarch64,        // AArch64 (little endian): aarch64
        bpfel,          // eBPF or extended BPF or 64-bit BPF (little endian)
        bpfeb,          // eBPF or extended BPF or 64-bit BPF (big endian)
        riscv64,        // RISC-V (64-bit): riscv64
        x86,            // X86: i[3-9]86
        x86_64,         // X86-64: amd64, x86_64
        wasm64,         // WebAssembly with 64-bit pointers
        ...
    };

    enum SubArchType {
        NoSubArch,
        ARMSubArch_v9,
        ARMSubArch_v8,
        ...
    };

    enum VendorType {
        UnknownVendor,
        Apple,
        PC,
        ...
    };

    enum OSType {
        UnknownOS,
        Linux,
        MacOSX,
        Win32,
        ...
    };

    enum EnvironmentType {
        UnknownEnvironment,
        GNU,
        Android,
        MSVC,
        ...
    };

    enum ObjectFormatType {
        UnknownObjectFormat,
        COFF,
        ELF,
        MachO,
        Wasm,
        ...
    };

    ArchType Arch{};

    SubArchType SubArch{};

    VendorType Vendor{};

    OSType OS{};

    EnvironmentType Environment{};

    ObjectFormatType ObjectFormat{};
    
}

// 默认triple
std::string TargetTriple = llvm::sys::getDefaultTargetTriple();

llvm::Triple computeTargetTriple(const Driver &D,
                                 StringRef TargetTriple,
                                 const ArgList &Args,
                                 ...) {
    // -target可以指定tripe以实现交叉编译
    if (const Arg *A = Args.getLastArg(options::OPT_target))
        TargetTriple = A->getValue();
    
    // 解析triple字符串
    // 常见的比如x86_64-unknown-linux-gnu按-分割依次表示arch/vendor/os/env
    llvm::Triple Target(llvm::Triple::normalize(TargetTriple));

    // 根据各种参数-m64/-march/-mcpu修正triple

    return Target;
}

```

工具链由`ToolChain`表示，用于确定每个triple的`编译/汇编/链接`工具

```c++

class ToolChain {
public:
    enum FileType { FT_Object, FT_Static, FT_Shared };

private:
    const Driver &D;
    llvm::Triple Triple;
    const llvm::opt::ArgList &Args;

    // 搜索lib/file/program的路径
    path_list LibraryPaths;
    path_list FilePaths;
    path_list ProgramPaths;

    // 用于编译/汇编/链接的工具
    mutable std::unique_ptr<Tool> Clang;
    mutable std::unique_ptr<Tool> Assemble;
    mutable std::unique_ptr<Tool> Link;

protected:
    virtual Tool *buildAssembler() const;
    virtual Tool *buildLinker() const;
    virtual Tool *buildStaticLibTool() const;
    // 根据处理步骤选择工具
    virtual Tool *getTool(Action::ActionClass AC) const;

public:
    virtual Tool *SelectTool(const JobAction &JA) const;
}

// 根据处理步骤选择工具
Tool *ToolChain::SelectTool(const JobAction &JA) const {
    // 选择clang自带的编译工具
    if (isa<PreprocessJobAction>(JA) && 
        isa<PrecompileJobAction>(JA) &&
        isa<CompileJobAction>(JA) && 
        isa<BackendJobAction>(JA) &&
        isa<ExtractAPIJobAction>(JA)) {
        return getClang();
    }

    Action::ActionClass AC = JA.getKind();

    // 选择clang内置的汇编器
    if (AC == Action::AssembleJobClass && useIntegratedAs())
        return getClangAs();

    // 选择其他汇编和链接工具
    return getTool(AC);
}

Tool *ToolChain::getTool(Action::ActionClass AC) const {
    switch (AC) {
    case Action::AssembleJobClass:
        return getAssemble();
    case Action::LinkJobClass:
        return getLink();
    case Action::StaticLibJobClass:
        return getStaticLibTool();

    case Action::CompileJobClass:
    case Action::PrecompileJobClass:
    case Action::PreprocessJobClass:
    case Action::ExtractAPIJobClass:
    case Action::AnalyzeJobClass:
    case Action::MigrateJobClass:
    case Action::VerifyPCHJobClass:
    case Action::BackendJobClass:
        return getClang();
    ...
    }
}

// clang内置的编译工具
Tool *ToolChain::getClang() const {
  if (!Clang)
    Clang.reset(new tools::Clang(*this, useIntegratedBackend()));
  return Clang.get();
}

// clang内置的汇编工具
Tool *ToolChain::buildAssembler() const {
  return new tools::ClangAs(*this);
}

Tool *ToolChain::buildLinker() const {
  llvm_unreachable("Linking is not supported by this toolchain");
}

Tool *ToolChain::buildStaticLibTool() const {
  llvm_unreachable("Creating static lib is not supported by this toolchain");
}

```

每个编译/汇编/链接工具由`Tool`表示

```c++

class Tool {
    /// The tool name (for debugging).
    const char *Name;
    
    /// The tool chain this tool is a part of.
    const ToolChain &TheToolChain;

public:
    virtual bool hasIntegratedAssembler() const { return false; }
    virtual bool hasIntegratedBackend() const { return true; }
    virtual bool canEmitIR() const { return false; }
    virtual bool hasIntegratedCPP() const = 0;
    virtual bool isLinkJob() const { return false; }

    // 构造JobAction对应的执行命令
    virtual void ConstructJob(Compilation &C, const JobAction &JA,
                              const InputInfo &Output,
                              const InputInfoList &Inputs,
                              const llvm::opt::ArgList &TCArgs,
                              const char *LinkingOutput) const = 0;
}

```

clang内置的编译命令构造过程如下：

```c++

// 构造的结构就是上文`build66/bin/clang -fno-integrated-as -### demo/main.c`的第一条编译指令
void Clang::ConstructJob(Compilation &C, const JobAction &JA,
                         const InputInfo &Output, const InputInfoList &Inputs,
                         const ArgList &Args, const char *LinkingOutput) const {
    ArgStringList CmdArgs;

    // Invoke ourselves in -cc1 mode.
    CmdArgs.push_back("-cc1");

    // Add the "effective" target triple.
    CmdArgs.push_back("-triple");
    CmdArgs.push_back(Args.MakeArgString(TripleStr));

    // 确定目标类型的核心参数
    if (isa<PreprocessJobAction>(JA)) {
        // 预处理
        CmdArgs.push_back("-E");
    } else if (isa<AssembleJobAction>(JA)) {
        CmdArgs.push_back("-emit-obj");
    } else {
        if (JA.getType() == types::TY_Nothing) {
            // 只分析语法
            CmdArgs.push_back("-fsyntax-only");
        } else if (JA.getType() == types::TY_LLVM_IR ||
                   JA.getType() == types::TY_LTO_IR) {
            // 产生文本格式的中间代码
            CmdArgs.push_back("-emit-llvm");
        } else if (JA.getType() == types::TY_LLVM_BC ||
                   JA.getType() == types::TY_LTO_BC) {
            // 产生二进制格式的中间代码
            CmdArgs.push_back("-emit-llvm-bc");
        } else if (JA.getType() == types::TY_PP_Asm) {
            // 产生编译加汇编直接产生obj
            CmdArgs.push_back("-S");
        }
    }

    // 构造其他参数

    // 输出文件
    if (Output.isFilename()) {
        CmdArgs.push_back("-o");
        CmdArgs.push_back(Output.getFilename());
    }

    // 输入文件
    for (const InputInfo &Input : FrontendInputs) {
        if (Input.isFilename())
            CmdArgs.push_back(Input.getFilename());
        else
            Input.getInputArg().renderAsInput(Args, CmdArgs);
    }

    // 注册构造的Command
    if (D.CC1Main && !D.CCGenDiagnostics) {
        // Invoke the CC1 directly in this process
        // 直接在当前进程执行编译任务，便于调试
        C.addCommand(std::make_unique<CC1Command>(
            JA, *this, ResponseFileSupport::AtFileUTF8(), Exec, CmdArgs, Inputs,
            Output, D.getPrependArg()));
    } else {
        C.addCommand(std::make_unique<Command>(
            JA, *this, ResponseFileSupport::AtFileUTF8(), Exec, CmdArgs, Inputs,
            Output, D.getPrependArg()));
    }
}

```

clang内置的汇编命令构造过程如下：

```c++

void ClangAs::ConstructJob(Compilation &C, const JobAction &JA,
                           const InputInfo &Output, const InputInfoList &Inputs,
                           const ArgList &Args,
                           const char *LinkingOutput) const {
    ArgStringList CmdArgs;

    // Invoke ourselves in -cc1as mode.
    CmdArgs.push_back("-cc1as");

    // Add the "effective" target triple.
    CmdArgs.push_back("-triple");
    CmdArgs.push_back(Args.MakeArgString(TripleStr));

    // 拼接其他参数
    
    // 注册构造的Command
    const char *Exec = getToolChain().getDriver().getClangProgramPath();
    if (D.CC1Main && !D.CCGenDiagnostics) {
        // Invoke cc1as directly in this process.
        C.addCommand(std::make_unique<CC1Command>(
            JA, *this, ResponseFileSupport::AtFileUTF8(), Exec, CmdArgs, Inputs,
            Output, D.getPrependArg()));
    } else {
        C.addCommand(std::make_unique<Command>(
            JA, *this, ResponseFileSupport::AtFileUTF8(), Exec, CmdArgs, Inputs,
            Output, D.getPrependArg()));
    }
}

```

选择工具链的过程如下：

```c++

const ToolChain &Driver::getToolChain(const ArgList &Args,
                                      const llvm::Triple &Target) const {
    // 每个target注册的默认工具链
    auto &TC = ToolChains[Target.str()];

    if (!TC) {
        // 修正特殊的工具链
        switch (Target.getOS()) {
        case llvm::Triple::Darwin:
        case llvm::Triple::MacOSX:
        case llvm::Triple::IOS:
            TC = std::make_unique<toolchains::DarwinClang>(*this, Target, Args);
            break;
        case llvm::Triple::Linux:
            TC = std::make_unique<toolchains::Linux>(*this, Target, Args);
            break;
        case llvm::Triple::Win32:
            switch (Target.getEnvironment()) {
            default:
                if (Target.isOSBinFormatELF())
                    TC = std::make_unique<toolchains::Generic_ELF>(*this, Target, Args);
                else if (Target.isOSBinFormatMachO())
                    TC = std::make_unique<toolchains::MachO>(*this, Target, Args);
                else
                    TC = std::make_unique<toolchains::Generic_GCC>(*this, Target, Args);
                break;
            case llvm::Triple::GNU:
                TC = std::make_unique<toolchains::MinGW>(*this, Target, Args);
                break;
            case llvm::Triple::Itanium:
                TC = std::make_unique<toolchains::CrossWindowsToolChain>(*this, Target, Args);
                break;
            case llvm::Triple::MSVC:
            case llvm::Triple::UnknownEnvironment:
                if (Args.getLastArgValue(options::OPT_fuse_ld_EQ)
                        .starts_with_insensitive("bfd"))
                    TC = std::make_unique<toolchains::CrossWindowsToolChain>(*this, Target, Args);
                else
                    TC = std::make_unique<toolchains::MSVCToolChain>(*this, Target, Args);
                break;
            }
            break;

            ...
        }
    }

    return *TC;
}


// linux默认工具链
class LLVM_LIBRARY_VISIBILITY Linux : public Generic_ELF {
    
    ...

protected:
    Tool *buildAssembler() const override;
    Tool *buildLinker() const override;
    Tool *buildStaticLibTool() const override;
}

// 调用系统默认汇编工具：生成上文的第2条指令
void tools::gnutools::Assembler::ConstructJob(Compilation &C,
                                              const JobAction &JA,
                                              const InputInfo &Output,
                                              const InputInfoList &Inputs,
                                              const ArgList &Args,
                                              const char *LinkingOutput) const {
    ArgStringList CmdArgs;

    const char *DefaultAssembler = "as";

    switch (getToolChain().getArch()) {
    case llvm::Triple::x86:
        CmdArgs.push_back("--32");
        break;
    case llvm::Triple::x86_64:
        if (getToolChain().getTriple().isX32())
            CmdArgs.push_back("--x32");
        else
            CmdArgs.push_back("--64");
        break;

    case llvm::Triple::riscv32:
    case llvm::Triple::riscv64: {
        StringRef ABIName = riscv::getRISCVABI(Args, getToolChain().getTriple());
        CmdArgs.push_back("-mabi");
        CmdArgs.push_back(ABIName.data());
        StringRef MArchName = riscv::getRISCVArch(Args, getToolChain().getTriple());
        CmdArgs.push_back("-march");
        CmdArgs.push_back(MArchName.data());
        if (!Args.hasFlag(options::OPT_mrelax, options::OPT_mno_relax, true))
            Args.addOptOutFlag(CmdArgs, options::OPT_mrelax, options::OPT_mno_relax);
        break;
    }

    case llvm::Triple::aarch64:
    case llvm::Triple::aarch64_be: {
        CmdArgs.push_back(getToolChain().getArch() == llvm::Triple::aarch64_be ? "-EB" : "-EL");
        Args.AddLastArg(CmdArgs, options::OPT_march_EQ);
        normalizeCPUNamesForAssembler(Args, CmdArgs);
        break;
    }
    
    ...
    }

    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());

    for (const auto &II : Inputs)
        CmdArgs.push_back(II.getFilename());

    // 从工具链的默认路径下搜索汇编器的路径
    const char *Exec = Args.MakeArgString(getToolChain().GetProgramPath(DefaultAssembler));
    // 注册拼接的命令
    C.addCommand(std::make_unique<Command>(JA, *this,
                                           ResponseFileSupport::AtFileCurCP(),
                                           Exec, CmdArgs, Inputs, Output));
}

// 调用系统默认链接工具：生成上文的第3条指令
void tools::gnutools::Linker::ConstructJob(Compilation &C, const JobAction &JA,
                                           const InputInfo &Output,
                                           const InputInfoList &Inputs,
                                           const ArgList &Args,
                                           const char *LinkingOutput) const {
    const bool IsStaticPIE = getStaticPIE(Args, ToolChain);
    const bool IsStatic = getStatic(Args);

    ArgStringList CmdArgs;

    ToolChain.addExtraOpts(CmdArgs);

    CmdArgs.push_back("--eh-frame-hdr");

    if (Triple.isRISCV())
        CmdArgs.push_back("-X");

    const bool IsShared = Args.hasArg(options::OPT_shared);
    if (IsShared)
        CmdArgs.push_back("-shared");

    if (IsStatic) {
        CmdArgs.push_back("-static");

    ...

    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());

    // 链接标准库
    if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nostartfiles, options::OPT_r)) {
        if (!Args.hasArg(options::OPT_shared)) {
            CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crt1.o")));
        }

        CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crti.o")));
    }

    // 需要透传给linker的参数
    Args.addAllArgs(CmdArgs, {options::OPT_L, options::OPT_u});

    AddLinkerInputs(ToolChain, Inputs, Args, CmdArgs, JA);

    // 链接c标准库
    if (!Args.hasArg(options::OPT_nolibc))
        CmdArgs.push_back("-lc");
    
    AddRunTimeLibs(ToolChain, D, CmdArgs, Args);

    CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crtn.o")));

    ...

    Args.AddAllArgs(CmdArgs, options::OPT_T);

    // 注册拼接的命令
    const char *Exec = Args.MakeArgString(ToolChain.GetLinkerPath());
    C.addCommand(std::make_unique<Command>(JA, *this,
                                           ResponseFileSupport::AtFileCurCP(),
                                           Exec, CmdArgs, Inputs, Output));
  }

}

```

### 收集输入文件

收集编译命令指定的输入文件，判断每个文件的类型

```c++

void Driver::BuildInputs(const ToolChain &TC, DerivedArgList &Args,
                         InputList &Inputs) const {
    types::ID InputType = types::TY_Nothing;

    for (Arg *A : Args) {
        if (A->getOption().getKind() == Option::InputClass) {
            types::ID Ty = types::TY_INVALID;

            // 首次推断文件类型
            if (InputType == types::TY_Nothing) {
                // 根据后缀确定文件类型
                if (const char *Ext = strrchr(Value, '.'))
                    Ty = TC.LookupTypeForExtension(Ext + 1);
                
                // 根据参数修正文件类型
            } 

            // 文件去重
            if (DiagnoseInputExistence(Args, Value, Ty, /*TypoCorrect=*/true))
                Inputs.push_back(std::make_pair(Ty, A));
        } else if (A->getOption().hasFlag(options::LinkerInput)) {
            // 链接输入obj文件
            Inputs.push_back(std::make_pair(types::TY_Object, A));
        }
    }
}

// 根据扩展确定文件类型
types::ID types::lookupTypeForExtension(llvm::StringRef Ext) {
  return llvm::StringSwitch<types::ID>(Ext)
      .Case("c", TY_C)
      .Case("C", TY_CXX)
      .Case("h", TY_CHeader)
      .Case("H", TY_CXXHeader)
      .Case("i", TY_PP_C)
      .Case("o", TY_Object)
      .Case("S", TY_Asm)
      .Case("s", TY_PP_Asm)
      .Case("bc", TY_LLVM_BC)
      .Case("cc", TY_CXX)
      .Case("CC", TY_CXX)
      .Case("hh", TY_CXXHeader)
      .Case("ii", TY_PP_CXX)
      .Case("ll", TY_LLVM_IR)
      .Case("asm", TY_PP_Asm)
      .Case("ast", TY_AST)
      .Case("cpp", TY_CXX)
      .Case("CPP", TY_CXX)
      .Case("c++", TY_CXX)
      .Case("C++", TY_CXX)
      .Case("cxx", TY_CXX)
      .Case("CXX", TY_CXX)
      .Case("hpp", TY_CXXHeader)
      .Case("hxx", TY_CXXHeader)
      .Case("pch", TY_PCH)
      .Case("pcm", TY_ModuleFile)
      .Default(TY_INVALID);
}
```

### 逻辑执行计划

源文件转换过程划分为6个阶段

```c++

namespace phases {
    enum ID {
        Preprocess,
        Precompile,
        Compile,
        Backend,
        Assemble,
        Link,
        ...
    };
}

```

然后就是2个问题：当前输入的文件处在哪个阶段？最终目标在哪个阶段？

```c++
// 根据参数确定最终阶段
phases::ID Driver::getFinalPhase(const DerivedArgList &DAL,
                                 Arg **FinalPhaseArg) const {
    phases::ID FinalPhase;
    if (DAL.getLastArg(options::OPT_E)) {
        FinalPhase = phases::Preprocess;
    } else if (DAL.getLastArg(options::OPT__precompile)) {
        FinalPhase = phases::Precompile;
    } else if (DAL.getLastArg(options::OPT_fsyntax_only) || 
               DAL.getLastArg(options::OPT_emit_ast)) {
        FinalPhase = phases::Compile;
    } else if (DAL.getLastArg(options::OPT_S)) {
        FinalPhase = phases::Backend;
    } else if (DAL.getLastArg(options::OPT_c)) {
        FinalPhase = phases::Assemble;
    } else {
        FinalPhase = phases::Link;
    }
    return FinalPhase;
}

```

确定输入文件所在的阶段以及需要的转换是通过查表法完成的

```c++

// 字段含义: ID表示类型，TEMP_SUFFIX表示源文件后缀，最后的参数表示需要进行的转换
#define TYPE(NAME, ID, PP_TYPE, TEMP_SUFFIX, ...)

// clang/Driver/Types.def
TYPE("c",                        C,            PP_C,            "c",      phases::Preprocess, phases::Compile, phases::Backend, phases::Assemble, phases::Link)

// C family input files to precompile.
TYPE("c-header-cpp-output",      PP_CHeader,   INVALID,         "i",      phases::Precompile)
TYPE("c-header",                 CHeader,      PP_CHeader,      "h",      phases::Preprocess, phases::Precompile)

TYPE("ir",                       LLVM_IR,      INVALID,         "ll",     phases::Compile, phases::Backend, phases::Assemble, phases::Link)
TYPE("ir",                       LLVM_BC,      INVALID,         "bc",     phases::Compile, phases::Backend, phases::Assemble, phases::Link)

// Misc.
TYPE("ast",                      AST,          INVALID,         "ast",    phases::Compile, phases::Backend, phases::Assemble, phases::Link)
TYPE("precompiled-header",       PCH,          INVALID,         "pch",    phases::Compile, phases::Backend, phases::Assemble, phases::Link)
TYPE("object",                   Object,       INVALID,         "o",      phases::Link)

```

```c++

// 构造执行计划
void Driver::BuildActions(Compilation &C, DerivedArgList &Args,
                          const InputList &Inputs, ActionList &Actions) const {
    for (auto &I : Inputs) {
        types::ID InputType = I.first;
        const Arg *InputArg = I.second;

        // 计算文件类型到目标类型的phase列表
        auto PL = types::getCompilationPhases(*this, Args, InputType);
        if (PL.empty())
            continue;
        
        // pipeline第一层：source
        Action *Current = C.MakeAction<InputAction>(*InputArg, InputType);

        for (phases::ID Phase : PL) {
            // 收集链接阶段的输入文件
            if (Phase == phases::Link) {
                LinkerInputs.push_back(Current);
                Current = nullptr;
                break;
            }

            // 转换到下一个阶段需要的action
            Action *NewCurrent = ConstructPhaseAction(C, Args, Phase, Current);
            {
                switch (Phase) {
                case phases::Preprocess: {
                    OutputTy = Input->getType();
                    OutputTy = types::getPreprocessedType(OutputTy);
                    return C.MakeAction<PreprocessJobAction>(Input, OutputTy);
                }
                case phases::Precompile: {
                    types::ID OutputTy = getPrecompiledType(Input->getType());
                    return C.MakeAction<PrecompileJobAction>(Input, OutputTy);
                }
                case phases::Compile: {
                    if (Args.hasArg(options::OPT_fsyntax_only))
                        return C.MakeAction<CompileJobAction>(Input, types::TY_Nothing);
                    if (Args.hasArg(options::OPT_emit_ast))
                        return C.MakeAction<CompileJobAction>(Input, types::TY_AST);
                    return C.MakeAction<CompileJobAction>(Input, types::TY_LLVM_BC);
                }
                case phases::Backend: {
                    if (Args.hasArg(options::OPT_emit_llvm)) {
                        types::ID Output = Args.hasArg(options::OPT_S) ? types::TY_LLVM_IR
                                                                       : types::TY_LLVM_BC;
                        return C.MakeAction<BackendJobAction>(Input, Output);
                    }
                    return C.MakeAction<BackendJobAction>(Input, types::TY_PP_Asm);
                }
                case phases::Assemble:
                    return C.MakeAction<AssembleJobAction>(std::move(Input), types::TY_Object);
                }
            }

            Current = NewCurrent;
        }

        // 每个input最终对应一个action
        if (Current)
            Actions.push_back(Current);
    }

    // 链接器合并多个输入
    if (!LinkerInputs.empty()) {
        Action *LA;
        if (ShouldEmitStaticLibrary(Args)) {
            LA = C.MakeAction<StaticLibJobAction>(LinkerInputs, types::TY_Image);
        } else {
            LA = C.MakeAction<LinkJobAction>(LinkerInputs, types::TY_Image);
        }
        Actions.push_back(LA);
    }
}

```

### 物理执行计划

```c++

void Driver::BuildJobs(Compilation &C) const {

    // 为每个输入的源文件成物理job
    for (Action *A : C.getActions()) {
        BuildJobsForAction(C, A, &C.getDefaultToolChain(),
                            /*BoundArch*/ StringRef(),
                            /*AtTopLevel*/ true,
                            /*MultipleArchs*/ ArchNames.size() > 1,
                            /*LinkingOutput*/ LinkingOutput, CachedResults,
                            /*TargetDeviceOffloadKind*/ Action::OFK_None);
    }

}

InputInfoList Driver::BuildJobsForAction(
    Compilation &C, const Action *A, const ToolChain *TC, StringRef BoundArch,
    bool AtTopLevel, bool MultipleArchs, const char *LinkingOutput, ...) const {
    
    // action递归的终点：输入的源文件
    if (const InputAction *IA = dyn_cast<InputAction>(A)) {
        const Arg &Input = IA->getInputArg();
        const char *Name = Input.getValue();
        return {InputInfo(A, Name, /* _BaseInput = */ Name)};
    }

    ActionList Inputs = A->getInputs();

    const JobAction *JA = cast<JobAction>(A);

    // 计算从input到当前action需要的转换工具
    ToolSelector TS(JA, *TC, C, ...);
    const Tool *T = TS.getTool(Inputs, ...);

    // 递归处理: 获取当前action需要的输入
    InputInfoList InputInfos;
    for (const Action *Input : Inputs) {
        InputInfos.append(BuildJobsForAction(C, Input, TC, BoundArch, 
            false, MultipleArchs, LinkingOutput, ...));
    }

    // Always use the first file input as the base input.
    const char *BaseInput = InputInfos[0].getBaseInput();
    for (auto &Info : InputInfos) {
        if (Info.isFilename()) {
            BaseInput = Info.getBaseInput();
            break;
        }
    }

    // 计算当前action的输出路径，中间的action创建临时文件
    // action之间通过这些中间文件传递数据
    InputInfo Result = InputInfo(A, GetNamedOutputPath(C, *JA, BaseInput, ...), BaseInput);

    // 组装命令行实现从InputInfos到Result
    T->ConstructJob(C, *JA, Result, InputInfos,
          C.getArgsForToolChain(TC, ...), LinkingOutput);

    return {Result};
}

// 根据当前的输入和输出选择工具
const Tool *getTool(ActionList &Inputs, ...) {
    SmallVector<JobActionInfo, 5> ActionChain(1);

    // 当前的action作为种子
    ActionChain.back().JA = BaseAction;
    while (ActionChain.back().JA) {
        const Action *CurAction = ActionChain.back().JA;

        // Grow the chain by one element.
        ActionChain.resize(ActionChain.size() + 1);
        JobActionInfo &AI = ActionChain.back();

        // 遍历逻辑执行计划的pipeline
        AI.JA = getPrevDependentAction(CurAction->getInputs(), ...);
        {
            Action *CurAction = *Inputs.begin();
            return dyn_cast<JobAction>(CurAction);
        }
    }

    // 去除末尾的null
    ActionChain.pop_back();

    // 根据ActionChain[-1]选择工具，然后判断是否恰好支持其他Action
    const Tool *T = combineAssembleBackendCompile(ActionChain, Inputs, ...);
    if (!T)
        T = combineAssembleBackend(ActionChain, Inputs, ...);
    if (!T)
        T = combineBackendCompile(ActionChain, Inputs, ...);
    if (!T) {
        // 预处理和预编译都由clang处理
        Inputs = BaseAction->getInputs();
        T = TC.SelectTool(*BaseAction);
    }

    combineWithPreprocessor(T, Inputs, ...);
    return T;
}

```

### 执行计划

物理执行计划由一组`Command`构成

```c++

/// Command - An executable path/name and argument vector to execute.
class Command {
    /// Source - The action which caused the creation of this job.
    const Action &Source;

    /// Tool - The tool which caused the creation of this job.
    const Tool &Creator;

     /// Whether and how to generate response files if the arguments are too long.
    ResponseFileSupport ResponseSupport;

    /// The executable to run.
    const char *Executable;

    /// Optional argument to prepend.
    const char *PrependArg;

    /// The list of program arguments (not including the executable).
    llvm::opt::ArgStringList Arguments;

    /// The list of program inputs.
    std::vector<InputInfo> InputInfoList;

    /// The list of program arguments which are outputs. May be empty.
    std::vector<std::string> OutputFilenames;

    /// See Command::setEnvironment
    std::vector<const char *> Environment;

    /// Optional redirection for stdin, stdout, stderr.
    std::vector<std::optional<std::string>> RedirectFiles;

    ...

    virtual void Print(llvm::raw_ostream &OS, ...) const;

    virtual int Execute(ArrayRef<std::optional<StringRef>> Redirects, ...) const;
    {
        std::optional<ArrayRef<StringRef>> Env;
        if (!Environment.empty()) {
            Env = ArrayRef(llvm::toStringRefArray(Environment.data()));
        }

        Argv.push_back(Executable);
        if (PrependArg)
            Argv.push_back(PrependArg);
        Argv.append(Arguments.begin(), Arguments.end());
        Argv.push_back(nullptr);
        auto Args = llvm::toStringRefArray(Argv.data());

        // 可执行文件/参数/环境变量/IO重定向
        return llvm::sys::ExecuteAndWait(Executable, Args, Env, Redirects,
                                /*secondsToWait*/ 0, /*memoryLimit*/ 0, ...);
        {
            ProcessInfo PI;

            // Create a child process.
            int child = fork();
            switch (child) {
            // Child process: Execute the program.
            case 0: {
                std::string PathStr = std::string(Program);
                if (Envp != nullptr)
                    execve(PathStr.c_str(), const_cast<char **>(Argv), 
                                            const_cast<char **>(Envp));
                else
                    execv(PathStr.c_str(), const_cast<char **>(Argv));
            }
            }

            PI.Pid = child;
            PI.Process = child;

            // 等待子进程结束
            ProcessInfo Result = Wait(PI, ...);
            return Result.ReturnCode;
        }
    }
}

```

正常的命令是在子进程中执行的，为了便于调试，编译命令做了特殊处理

```c++

class CC1Command : public Command {

    int Execute(ArrayRef<std::optional<StringRef>> Redirects, ...) const;
    {
        // 非调试直接在子进程里执行
        if (!InProcess)
            return Command::Execute(Redirects, ErrMsg, ExecutionFailed);

        SmallVector<const char *, 128> Argv;
        Argv.push_back(getExecutable());
        Argv.append(getArguments().begin(), getArguments().end());

        const Driver &D = getCreator().getToolChain().getDriver();

        // 直接调用主流程中设置的CC1Main
        return D.CC1Main(Argv);
    }

}

```

依次执行指令

```c++

int Driver::ExecuteCompilation(Compilation &C, ...) {
    // 只打印要执行的命令: clang -fdriver-only -v demo/main.c -o demo/main
    if (C.getArgs().hasArg(options::OPT_fdriver_only)) {
        if (C.getArgs().hasArg(options::OPT_v))
            C.getJobs().Print(llvm::errs(), "\n", true);

        C.ExecuteJobs(C.getJobs(), FailingCommands, /*LogOnly=*/true);
        return 0;
    }

    // Just print if -### was present.
    if (C.getArgs().hasArg(options::OPT__HASH_HASH_HASH)) {
        C.getJobs().Print(llvm::errs(), "\n", true);
        return 0;
    }

    // 执行job
    C.ExecuteJobs(C.getJobs(), ...);
    return 0;
}

void Compilation::ExecuteJobs(const JobList &Jobs, ..., bool LogOnly) const {
    for (const auto &Job : Jobs) {
        // 判断前置job是否成功: 是否在FailingCommands中
        if (!InputsOk(Job, FailingCommands))
            continue;

        ExecuteCommand(Job, FailingCommand, LogOnly);
        {
            // 打印命令
            if (getDriver().CCPrintOptions || getArgs().hasArg(options::OPT_v)) {
                C.Print(*OS, "\n", /*Quote=*/getDriver().CCPrintOptions);
            }

            // 只打印不执行
            if (LogOnly)
                return 0;

            // 执行命令
            C.Execute(Redirects, &Error, &ExecutionFailed);
        }
    }
}

```

## 总结

driver之所以叫driver就在于它自己并不直接参与编译的过程，它只是根据输入源文件类型和输出文件类型构造逻辑执行计划，然后根据选择的工具链把逻辑执行计划转换为可执行的物理执行计划，物理计划的每个步骤都是一个命令行，`fork`之后在子进程中执行，然后等待执行结果。

