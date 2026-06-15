# MiniDumpInproc

Windows CMake 工程，提供进程内写 dump 的最小封装：

```cpp
// 无需任何初始化调用：库在模块加载时自动预解析所需 ntdll 例程。
BOOL WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    ULONG64 MaxFileSize);   // 0 = 不限制
```


## 设计约束

- `WriteMiniDumpInproc` 不调用 `MiniDumpWriteDump`，只复用 `dbghelp.h` 里的 minidump 类型定义。
- 参考 `NativeDumpCpp` 和 `dbgcore!MiniDumpWriteDump` 的思路自行组装 minidump；基础 stream 固定包含 `SystemInfo`、`MiscInfo`、`ModuleList`、`ThreadList`，传入异常信息时额外写 `ExceptionStream`。
- `DumpType` 已开始按标志位组合裁剪：`MiniDumpWithFullMemory` 写 `Memory64List` 和完整内存；未指定 full memory 时写 `MemoryList`，默认包含线程栈；`MiniDumpWithFullMemoryInfo` 写 `MemoryInfoList`；`MiniDumpWithThreadInfo` / `MiniDumpWithProcessThreadData` 写 `ThreadInfoList`；`MiniDumpWithDataSegs` 写可写 image 数据区域；`MiniDumpWithIndirectlyReferencedMemory` 做**多层 BFS 指针扫描**（见下）；`MiniDumpScanMemory` 目前不做模块引用标记；`MiniDumpIgnoreInaccessibleMemory` 允许坏页补零继续；`MiniDumpWithUnloadedModules` 目前写入合法空 stream 作为结构占位；`MiniDumpWithHandleData` 与 `MiniDumpWithTokenInformation` 不写入对应 stream（即使传入这些标志也会被忽略，仅保留在 `header.Flags`）。

- **`MaxFileSize` 与优先级裁剪**：`MaxFileSize=0` 表示不限制；非 0 时作为软上限，按优先级填充直至逼近上限。强制层（始终写入，即使超限——否则 dump 无意义）：Header、SystemInfo、MiscInfo、ModuleList、ThreadList + 全部线程 context、ExceptionStream、以及**所有线程栈**。可裁剪层按优先级从高到低：(1) `MiniDumpWithDataSegs` 可写数据段（预算不足则整体放弃），(2) `MiniDumpWithIndirectlyReferencedMemory` 间接引用内存（最低优先级，按剩余预算逐页截断）。

- **多层间接引用扫描**：间接内存采用按层 BFS。第 1 层 = 线程栈上指针指向的 4K 非镜像可读页；第 2/3 层 = 从已收集页里再扫出的指针所指向的页（深度上限 `kIndirectMaxScanLayers`，默认 3，相关性随层数衰减）。优先级：**崩溃/异常线程的整棵引用子树（第 1→2→3 层）** 先于其它线程的子树收集，从而在预算紧张时优先保留与崩溃最相关的数据。去重用 scratch 缓冲上半区的开放寻址哈希集（O(1)，避免多层后退化为 O(n²)），并对 `VirtualQuery` 做单条区域缓存以降低聚簇指针的查询开销。收集总量受 `MaxFileSize` 预算与缓冲容量共同约束（不再有固定 2048 上限）。

- 不使用 STL、CRT 容器或显式堆分配；模块、线程和内存区域通过遍历 PEB / 预解析的 `NtQuerySystemInformation` / `VirtualQuery` 统计并流式写入。
- **一致性模型**：进入 `WriteMiniDumpInproc` 后会先 `SuspendThread` 冻结其余所有线程（句柄在冻结前一次性打开，避免冻结期间再取句柄表锁），并只做**一次**线程快照，固化成不可变的“线程计划”（TEB、栈范围、时间等）。之后的所有 stream（ThreadList、线程 context、ThreadInfoList、栈 MemoryList、间接引用扫描）都只读这份计划；`MiniDumpWithFullMemory` 的内存区域也在一次 `VirtualQuery` 遍历里固化成固定列表。这样“描述符里声明的大小”与“实际写入的字节”始终严格一致，不会因进程并发改动内存/栈而产生错位或损坏。线程 context 直接来自已冻结的线程，与采集到的栈字节同一时刻，回栈一致。函数返回（含中途异常）时统一恢复并关闭所有被冻结的线程。
- **并发崩溃串行化**：通过 `InterlockedCompareExchange` 单入口保护，多个线程同时崩溃时只有第一个写 dump，其余返回 `FALSE`（`ERROR_BUSY`），避免共享静态缓冲区被竞争。
- **自动初始化**：库在模块加载时（静态初始化阶段）自动预解析 `ntdll` 导出（`RtlGetVersion` / `NtQueryInformationThread` / `NtQuerySystemInformation`），无需也不再提供 `InitMiniDumpInproc()`；崩溃路径不会 lazy 调用 `GetModuleHandleW` / `GetProcAddress`。`WriteMiniDumpInproc` 入口另有一次幂等的兜底解析以应对异常的初始化顺序。
- **内存复用**：进程信息快照缓冲、全内存范围表、间接引用范围表/哈希集**复用同一块 scratch 缓冲**（这些用途在时间上互不重叠），整体静态占用显著下降。


- 文件由调用方打开并传入 `hFile`，函数内不构造路径、不创建文件、不分配大缓冲区。
- MSVC 构建下用 SEH 包住关键内存读取和写 dump 主流程，坏页会尽量以零页补齐。

注意：进程内 dump 天然不如独立守护进程/外部进程可靠；如果 PEB/LDR 链、当前线程栈或文件系统状态已损坏，任何进程内方案都不能保证 100% 成功。当前实现已支持部分 `MINIDUMP_TYPE` 的组合裁剪；`MiniDumpWithUnloadedModules` 仍只是空 stream 占位，`MiniDumpWithHandleData`、`MiniDumpWithTokenInformation` 已不再写入对应 stream，`MiniDumpWithIndirectlyReferencedMemory` 是无堆分配约束下的有限指针扫描实现。

### 已知残留风险与限制

- **栈溢出（`STATUS_STACK_OVERFLOW`）**：写 dump 仍跑在出问题的线程栈上，可能二次失败。若要覆盖此场景，建议从一个**专用的、预留了独立大栈的处理线程**调用 `WriteMiniDumpInproc`（崩溃线程把异常信息投递过去），而不是直接在崩溃线程的 SEH filter 里写。
- **冻结期理论死锁**：冻结其它线程后写 dump 仍会调用 `VirtualQuery`（地址空间锁）等；若某线程恰好在被冻结时独占持有这些锁，理论上可能阻塞。这是所有“挂起式”dump（含 dbghelp/breakpad）的固有取舍，本实现已尽量避免在崩溃路径使用堆/loader 锁来降低概率。
- **线程/模块上限**：线程计划上限 `kMaxThreads`（默认 1024）、模块上限 `kMaxModules`（默认 4096）、全内存区域上限 `kMaxFullMemoryRanges`（默认 65536）。超出部分会被截断，dump 仍结构合法但可能不完整；极少数情况下若异常线程未被枚举到，异常 context 槽位的指向可能不准确。
- **仅完整支持 x64/x86**：ARM64 下 PEB/TEB 段寄存器读取不可用，模块与栈信息会退化。
- **文件句柄需为同步句柄**：内部用同步 `WriteFile`，请勿传入 `FILE_FLAG_OVERLAPPED` 打开的句柄。

### 为什么不写 `HandleDataStream`

`MiniDumpWithHandleData` 已被有意去掉，原因如下：

- **崩溃现场能拿到的字段信息量太低**：进程内枚举句柄只能用 `NtQuerySystemInformation(SystemExtendedHandleInformation)`，它返回的有用字段仅 handle 值、`GrantedAccess`、`HandleAttributes` 和一个 `ObjectTypeIndex` 索引。WinDbg 由此只能列出"进程持有哪些 handle、访问掩码是多少"，无法显示**对象类型名**（`File`/`Event`/`Key`/`Section` 等）和**对象名**（设备路径、命名管道名、注册表路径、命名对象名等）。而排查句柄泄漏、文件占用、命名对象冲突时，真正有价值的恰恰是类型名和对象名。
- **补齐类型名/对象名需要调用崩溃路径上的危险 API**：要把 `ObjectTypeIndex` 翻成类型名、拿到对象名，必须对每个 handle 调用 `NtQueryObject(ObjectTypeInformation / ObjectNameInformation)`。这些调用在崩溃现场风险很高：`ObjectNameInformation` 对某些同步对象、socket、命名管道存在已知的**阻塞/挂起**问题；调用可能**内部分配堆内存**、按 handle 数量逐个查询开销大，与本实现"无显式堆分配、不在崩溃路径执行可能 hang 的调用"的约束冲突。
- **变长字符串与无堆约束冲突**：类型名/对象名是数量不定的变长字符串，存储通常需要动态缓冲或字符串池，与当前固定静态缓冲、无堆分配的设计相悖。
- **整体性价比低**：保留这个 stream 只能产出"handle 值 + 访问掩码 + 属性"的清单，对绝大多数崩溃分析没有实质帮助，却增加了 dump 体积和一次额外的系统信息查询。因此直接移除，比保留一个低价值字段更干净。

如果将来确实需要句柄类型/对象名，建议放到**非崩溃路径**采集（例如独立的健康巡检或泄漏检测线程），并对易挂起的对象类型设置超时保护，而不是在 `WriteMiniDumpInproc` 崩溃路径里默认开启。





## 构建

```powershell
cd d:\my_work\minidump
cmake -S . -B build -A x64
cmake --build build --config Release
```

Detours 以 git submodule 形式引入到 `third_party/Detours`，首次拉取后执行：

```powershell
git submodule update --init --recursive
```

默认会生成：

- `MiniDumpInproc`：库目标
- `MiniDumpInprocSample`：崩溃写 dump 示例，运行后在当前目录生成 `inproc_sample.dmp`
- `MiniDumpInprocStressTest`：多线程 + 多种真实崩溃压测（见下），父/子进程模型并自动校验 dump
- `MiniDumpWriteDumpAllocTrace`：基于 `third_party/Detours` 的 `MiniDumpWriteDump` 内存分配跟踪 demo
- `MiniDumpInprocHeapFailTest`：基于 Detours 将 `HeapAlloc` / `RtlAllocateHeap` / `VirtualAlloc` 等强制返回 `NULL`，验证 `WriteMiniDumpInproc` 的无堆分配路径


`MiniDumpWriteDumpAllocTrace` 会 hook `HeapCreate` / `HeapAlloc` / `HeapReAlloc` / `HeapFree` / `HeapDestroy` / `VirtualAlloc` / `VirtualFree`，调用系统 `MiniDumpWriteDump` 后输出：新建 heap、落在新建 heap 上的分配事件、其他 heap 事件、VirtualAlloc 计数。运行示例：

```powershell
cd d:\my_work\minidump\build\Release
.\MiniDumpWriteDumpAllocTrace.exe trace_test.dmp
```

`MiniDumpInprocHeapFailTest` 会覆盖以下极限场景：`HeapAlloc` 返回 `NULL`、`HeapReAlloc` 返回 `NULL`、`RtlAllocateHeap` / `RtlReAllocateHeap` 返回 `NULL`、`HeapCreate` / `RtlCreateHeap` 返回 `NULL`、`VirtualAlloc` 返回 `NULL`，以及包含 `MiniDumpWithIndirectlyReferencedMemory` 的富标志组合 dump，验证整条路径无任何 Heap/Virtual 分配。运行示例：


```powershell
cd d:\my_work\minidump\build\Release
.\MiniDumpInprocHeapFailTest.exe
```

`MiniDumpInprocStressTest` 以父/子进程模型逐场景验证稳定性：子进程拉起 150 个工作线程（每个在栈上挂一条 3 层指针链，专门喂给多层间接扫描），用**独立大栈的 dump 线程**写 dump（崩溃线程仅在过滤器里发信号 + 等待，从而即使栈溢出也能写出——这正是推荐的栈溢出处理范式），再触发真实崩溃：空指针写、栈溢出、释放后使用、堆元数据破坏；父进程随后解析 dump 校验 header、流集合并确认捕获了 100+ 线程。运行示例：

```powershell
cd d:\my_work\minidump\build\Release
.\MiniDumpInprocStressTest.exe
```

> 说明：堆元数据破坏在现代 Windows 上通常走 `__fastfail` 快速失败，**绕过所有进程内异常处理器**（VEH/SEH/UnhandledExceptionFilter 均收不到），因此这类崩溃在进程内无法写 dump——这是进程内方案的根本限制，压测里以 `INFO` 标记而非失败。


如不需要示例：


```powershell
cmake -S . -B build -A x64 -DMINIDUMP_INPROC_BUILD_SAMPLE=OFF
```

## 用法

```cpp
#include "minidump_inproc.h"

// 无需初始化调用：库在模块加载时已自动预解析所需 ntdll 例程。

LONG WINAPI Filter(PEXCEPTION_POINTERS ep)
{

    HANDLE hFile = CreateFileW(L"crash.dmp", GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;

    // 第 4 个参数是 dmp 文件大小软上限（字节），0 表示不限制。
    (void)WriteMiniDumpInproc(hFile, MiniDumpNormal, &mei, 0);
    CloseHandle(hFile);
    return EXCEPTION_EXECUTE_HANDLER;
}
```

> 栈溢出场景请参考 `examples/inproc_stress_test.cpp`：从一个预留独立大栈的专用 dump 线程调用 `WriteMiniDumpInproc`，崩溃线程只在过滤器里投递异常信息并等待。
