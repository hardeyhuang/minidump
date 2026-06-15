# MiniDumpInproc

Windows CMake 工程，提供进程内写 dump 的最小封装。

> **定位**：这是一个 **crash-path best-effort 的进程内 minidump writer**——不调用 `MiniDumpWriteDump`、无显式堆分配、不依赖 `dbghelp`、崩溃路径不走 loader/CRT 重路径。它在进程已部分损坏、且只能进程内自救（如被反作弊限制无法进程外 dump）时，**尽力**产出一个可打开、信息尽可能多的 dump，但**不承诺**在任意损坏程度下都成功或完整一致。若进程未受限、可接受外部进程，最可靠形态仍是 WerFault 式 out-of-process `MiniDumpWriteDump`。

封装签名：

```cpp
BOOL WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    ULONG64 MaxFileSize);   // 0 = 不限制
```


## 与 `MiniDumpWriteDump` 的对比

`WriteMiniDumpInproc` 不是 `MiniDumpWriteDump`（`dbgcore.dll` / `dbghelp.dll`）的简单封装，而是一套**为"被反作弊保护、只能进程内自救"场景重写**的实现。两者关键差异：

| 维度 | `WriteMiniDumpInproc`（本实现） | `MiniDumpWriteDump`（系统 API） |
|---|---|---|
| **运行位置** | **进程内**，对自身地址空间直接读写 | 既可进程内调用，也常由**外部进程**（如 WerFault）跨进程 dump 目标进程 |
| **反作弊兼容** | ✅ 适配 ACE 等**禁止进程外读内存**的场景——dump 由受保护进程自己产出 | ❌ 外部 dump 模式会被反作弊拦截；进程内调用又依赖 dbghelp（见下） |
| **依赖** | 仅复用 `dbghelp.h` 的**类型定义**，运行时只依赖 `ntdll` 几个已预解析的导出 | 运行时依赖 `dbgcore.dll` / `dbghelp.dll`，需 `LoadLibrary` / 导出解析 |
| **堆分配** | **无显式堆分配**，全部用固定静态 scratch 缓冲 | 内部**大量堆分配**（`HeapAlloc` / `VirtualAlloc`），堆损坏时易二次失败 |
| **崩溃路径安全性** | 专为崩溃现场设计：SEH 包裹、坏页补零、不走 loader 锁、不调用易挂起 API | 崩溃现场调用需要的堆/loader/加载 DLL 操作均可能在堆或加载器已损坏时失败 |
| **线程一致性** | 进入后**冻结其余线程 + 单次快照固化计划**，描述符与字节流一致（细节与例外见正文） | 由系统保证，进程内自我 dump 时同样面临活动进程一致性问题 |
| **并发崩溃** | `InterlockedCompareExchange` 单入口串行化，多线程同时崩溃只写一次 | 无内建串行化，需调用方自行加锁 |
| **大小控制** | 原生支持 `MaxFileSize` 软上限 + **优先级裁剪**（栈/context 强制，DataSegs、间接内存按预算逐层截断） | 无大小上限参数；体积由 `DumpType` 决定，要么全要么无 |
| **间接引用内存** | **多层 BFS 指针扫描**（崩溃线程子树优先，去重哈希 + VirtualQuery 缓存） | `MiniDumpWithIndirectlyReferencedMemory` 为单层引用，且依赖堆分配 |
| **功能完整度** | 裁剪实现：`HandleData` / `TokenInformation` 等**有意不写**（见下），`UnloadedModules` 仅占位 | **功能完整**：句柄、Token、卸载模块、回调扩展等全面支持 |
| **可扩展回调** | 无 `MINIDUMP_CALLBACK`（崩溃路径刻意保持简单） | 支持 `CallbackParam` 回调，可精细控制每个 stream/内存块 |
| **可靠性定位** | 进程内**兜底/降级**路径，天然不如外部进程可靠 | 外部进程模式是**最可靠**形态（地址空间独立） |

**选型建议**：
- 若进程**未被反作弊限制**、且能接受外部进程：首选 **WerFault 式 out-of-process `MiniDumpWriteDump`**（最可靠，规避在受损地址空间里自救）。
- 若进程**被 ACE 等反作弊保护、进程外无法读内存**：只能进程内自救，此时 `WriteMiniDumpInproc` 是更安全的选择——它规避了 `MiniDumpWriteDump` 在崩溃现场对堆/加载器/额外 DLL 的依赖。
- 两者可**并存**：正常情况用系统 API，受限或 dbghelp 不可用时降级到本实现。


## 设计约束

- `WriteMiniDumpInproc` 不调用 `MiniDumpWriteDump`，只复用 `dbghelp.h` 里的 minidump 类型定义。
- 参考 `dbgcore!MiniDumpWriteDump` 的思路自行组装 minidump；基础 stream 固定包含 `SystemInfo`、`MiscInfo`、`ModuleList`、`ThreadList`，传入异常信息时额外写 `ExceptionStream`。
- `DumpType` 按标志位组合裁剪输出内容，**支持程度见下表**。

### 支持的 `MINIDUMP_TYPE` 标志与支持程度

固定写入（与标志无关，始终产出）：`SystemInfoStream`、`MiscInfoStream`、`ModuleListStream`、`ThreadListStream` + 全部线程 `CONTEXT`；传入异常信息时附带 `ExceptionStream`。

| 标志 | 支持程度 | 说明 |
|---|---|---|
| `MiniDumpNormal` | ✅ 完整 | 基础流 + 全部线程栈（`MemoryList`），可还原各线程调用栈 |
| `MiniDumpWithFullMemory` | ✅ 完整 | 改写 `Memory64List`，dump 全部已提交可读区域；**忽略 `MaxFileSize`**（见下，避免按地址顺序截断时误丢高地址的线程栈） |
| `MiniDumpWithFullMemoryInfo` | ✅ 完整 | 写 `MemoryInfoList`（VirtualQuery 区域属性） |
| `MiniDumpWithThreadInfo` | ✅ 完整 | 写 `ThreadInfoList`（创建/内核/用户时间、起始地址等） |
| `MiniDumpWithProcessThreadData` | ✅ 同上 | 等价触发 `ThreadInfoList` |
| `MiniDumpWithDataSegs` | ✅ 完整 | **设置**=全量写可写 image 数据段（globals/statics），作为可裁剪层优先级 1，预算不足整体放弃；**不设**=数据段不再整段捕获，而是交给间接引用扫描"按需"收集（见下，适合超大全局块） |
| `MiniDumpWithIndirectlyReferencedMemory` | ✅ 增强 | **多层 BFS 指针扫描**（见下）；可裁剪层最低优先级，按剩余预算逐页截断。未设 `MiniDumpWithDataSegs` 时，可写数据段也作为扫描目标被"按引用"收集 |
| `MiniDumpIgnoreInaccessibleMemory` | ♾️ 始终生效 | 本实现**所有**内存区域（线程栈/数据段/间接引用/全内存）一律对不可读页补零、绝不因坏页失败；该标志因此**无论设不设都等效"已设"**，仅保留在 `header.Flags` |
| `MiniDumpScanMemory` | ⚠️ 忽略 | 不做模块引用标记，标志仅保留在 `header.Flags` |
| `MiniDumpWithUnloadedModules` | ❌ 不写 | 不写 `UnloadedModuleListStream`（进程内无可靠、无堆的卸载模块表来源），标志仅保留在 `header.Flags` |
| `MiniDumpWithHandleData` | ❌ 不写 | 见"为什么不写 `HandleDataStream`" |
| `MiniDumpWithTokenInformation` | ❌ 不写 | 崩溃路径采集 Token 价值低、易触发危险调用，标志仅保留在 `header.Flags` |
| 其它未列出标志 | ⚠️ 忽略 | 不报错，按未实现处理，仅保留在 `header.Flags` |

> 约定：表中"忽略/不写"的标志传入后**不会导致失败**，只是不产生对应内容；`header.Flags` 仍如实记录调用方请求的原始标志位，便于分析端识别意图。

- **`MaxFileSize` 与优先级裁剪（仅作用于选择性内存 dump）**：`MaxFileSize=0` 表示不限制；非 0 时作为软上限，按优先级填充直至逼近上限。强制层（始终写入，即使超限——否则 dump 无意义）：Header、SystemInfo、MiscInfo、ModuleList、ThreadList + 全部线程 context、ExceptionStream、以及**所有线程栈**。可裁剪层按优先级从高到低：(1) `MiniDumpWithDataSegs` 可写数据段（预算不足则整体放弃），(2) `MiniDumpWithIndirectlyReferencedMemory` 间接引用内存（最低优先级，按剩余预算逐页截断）。
  - `MaxFileSize` 类型为 `ULONG64`，取值上不设人为上限，预算算术全程 64 位、不会溢出；填得过大只是"不裁剪"。
  - **软上限语义**：若 `MaxFileSize` 比强制层还小，强制层仍会写出，最终文件可能略超 `MaxFileSize`（保证 dump 有用）。
  - **`MiniDumpWithFullMemory` 忽略 `MaxFileSize`**：full memory dump 用 64 位 `Memory64List`，目标就是捕获**完整**的已提交可读区域。若对它套用字节预算，会按 `VirtualQuery` 的地址顺序（低→高）截断；而线程栈通常在高地址，小的 `MaxFileSize` 可能保留一堆低地址区域、却**把线程栈丢掉**，破坏调用栈还原——这恰恰是 full memory 使用者最不想要的。因此设置 `MiniDumpWithFullMemory` 时，**无论 `MaxFileSize` 取值多少都保留全部捕获区域**。需要受控体积请改用选择性内存 dump（栈强制保留，仅 DataSegs/间接内存按预算裁剪）。
  - **格式硬上限（4 GB）**：选择性内存 dump（非 `MiniDumpWithFullMemory`）的 `MemoryList` 用 32 位 RVA 寻址。内部把可裁剪层的有效预算上限设为略小于 4 GB，优先裁掉 DataSegs/间接内存。但**强制线程栈不受该预算约束**，极端情况下（如海量大栈线程）其字节总量仍可能把内存字节区推过 4 GB；此时不会产出 RVA 静默截断的损坏 dump，而是在布局阶段以 64 位精度复核内存字节区尾端，**超出即直接失败返回 `ERROR_FILE_TOO_LARGE`**。需要超过 4 GB 请用 `MiniDumpWithFullMemory`（64 位 `Memory64List`，仅受磁盘与进程已提交内存约束）。

- **多层间接引用扫描**：间接内存采用按层 BFS。第 1 层 = 线程栈上指针指向的 4K 可读页；第 2/3 层 = 从已收集页里再扫出的指针所指向的页（深度上限 `kIndirectMaxScanLayers`，默认 3，相关性随层数衰减）。优先级：**崩溃/异常线程的整棵引用子树（第 1→2→3 层）** 先于其它线程的子树收集，从而在预算紧张时优先保留与崩溃最相关的数据。去重用 scratch 缓冲上半区的开放寻址哈希集（O(1)，避免多层后退化为 O(n²)），并对 `VirtualQuery` 做单条区域缓存以降低聚簇指针的查询开销。收集总量受 `MaxFileSize` 预算与缓冲容量共同约束。

  扫描目标的取舍：**只读 image 页**（代码 `.text`、常量 `.rdata`）始终排除——它们能从模块文件还原，不值得占预算；**普通可读非镜像内存**（堆、私有、映射）一律可收；**可写 image 数据段**（全局/静态变量）是否参与取决于 `MiniDumpWithDataSegs`：
  - 未设 `MiniDumpWithDataSegs`：数据段**当作普通堆**对待，只收被指针链真正触达的 4K 页，并继续向下做多层扩散。对"全局数据块非常大"的工程尤其友好——不再整段灌入，只保留与崩溃相关的部分，受 `MaxFileSize` 预算约束。
  - 已设 `MiniDumpWithDataSegs`：数据段已整段全量捕获，并被纳入 known-range；间接扫描命中同一页时按重叠去重跳过，**不会重复收集**。

- 不使用 STL、CRT 容器或显式堆分配；模块、线程和内存区域通过遍历 PEB / 预解析的 `NtQuerySystemInformation` / `VirtualQuery` 统计并流式写入。
- **一致性模型**：进入 `WriteMiniDumpInproc` 后会先逐线程 `SuspendThread` **尽力冻结快照中的其余线程**（句柄在冻结前一次性打开，避免冻结期间再取句柄表锁），并只做**一次**线程快照，固化成不可变的“线程计划”（TEB、栈范围、时间等）。之后的与线程相关的 stream（ThreadList、线程 context、ThreadInfoList、栈 MemoryList、间接引用扫描）都只读这份计划；`MiniDumpWithFullMemory` 的内存区域也在一次 `VirtualQuery` 遍历里固化成固定列表，描述符与字节流严格一致。
  - **栈/线程 context 一致**：线程 context 直接来自已冻结的线程，与采集到的栈字节在同一冻结现场，回栈一致。例外：若使用专用 dump 线程范式（崩溃线程投递 `EXCEPTION_POINTERS` 给 dump 线程），异常线程的 context 来自崩溃发生时刻、其栈字节来自之后的冻结时刻，二者不是严格同一瞬间（实践中崩溃线程在投递后等待、不再前进，通常仍一致）。
  - **`MiniDumpWithDataSegs` 一致性较弱**：选择性 dump 里的可写数据段在计数 / 写描述符 / 写字节三个阶段分别重走 `VirtualQuery`（未像 full memory 那样固化成固定列表）。其余线程已冻结时地址空间通常稳定，但严格来说这部分不享有“描述符与字节流绝对一致”的保证（后续可优化为固化计划）。
- **并发崩溃串行化**：通过 `InterlockedCompareExchange` 单入口保护，多个线程同时崩溃时只有第一个写 dump，其余返回 `FALSE`（`ERROR_BUSY`），避免共享静态缓冲区被竞争。
- **初始化（强依赖加载期预解析，崩溃路径绝不走 loader）**：库在模块加载时（静态初始化阶段，`AutoInitInprocApis` 全局构造）自动预解析 `ntdll` 导出（`RtlGetVersion` / `NtQueryInformationThread` / `NtQuerySystemInformation`）。崩溃路径**绝不** lazy 调用 `GetModuleHandleW` / `GetProcAddress`（这些会取 loader 锁，崩溃现场可能已被持有或损坏）。若由于异常的初始化顺序导致加载期预解析未完成，`WriteMiniDumpInproc` 会直接失败返回 `FALSE`（`ERROR_NOT_READY`），而不是在崩溃路径触碰 loader。本库不提供、也不需要显式 `InitMiniDumpInproc()`。
- **内存复用**：进程信息快照缓冲、全内存范围表、间接引用范围表/哈希集**复用同一块 scratch 缓冲**（这些用途在时间上互不重叠），整体静态占用显著下降。


- 文件由调用方打开并传入 `hFile`，函数内不构造路径、不创建文件、不分配大缓冲区。
- MSVC 构建下用 SEH 包住关键内存读取和写 dump 主流程，坏页会尽量以零页补齐。
- **逐 stream 容错（内存严重破坏时不彻底失败）**：除"文件头 + stream 目录"这一最小结构外，每个 stream 的采集与写入都在**独立的 SEH 保护**下进行。如果在内存严重破坏的情况下某个 stream 采集时触发**访问违例（SEH fault）**，该 stream 会被**跳过**（其预排布的区域保持零填充），dump 继续写出其余所有 stream，而不是整体失败。计数阶段（模块/内存信息/栈/数据段/间接引用）的失败同样降级为"该部分为空"而非中止。
  - **当前精确语义**：被吞掉、可跳过的只有 **SEH 访问违例**；而 stream 写函数**显式返回 `FALSE`**（无论是文件 I/O 失败，还是个别采集函数如 `CaptureExceptionStreamInfo` 返回 `FALSE`）目前都会中止整个 dump。也就是说，"采集失败"与"I/O 失败"两类 `FALSE` 尚未在返回码层面区分。绝大多数情况下显式 `FALSE` 确实来自文件 I/O（句柄无效、磁盘写满），中止是合理的；后续可把"采集失败跳过 / I/O 失败中止"做成分层返回码以进一步细化。这样即使在受损进程里，也能尽量产出一个"残缺但可打开、信息尽可能多"的 dump。

### 已知残留风险与限制

- **栈溢出（`STATUS_STACK_OVERFLOW`）**：写 dump 仍跑在出问题的线程栈上，可能二次失败。若要覆盖此场景，建议从一个**专用的、预留了独立大栈的处理线程**调用 `WriteMiniDumpInproc`（崩溃线程把异常信息投递过去），而不是直接在崩溃线程的 SEH filter 里写。
- **冻结期理论死锁**：冻结其它线程后写 dump 仍会调用 `VirtualQuery`（地址空间锁）等；若某线程恰好在被冻结时独占持有这些锁，理论上可能阻塞。这是所有“挂起式”dump（含 dbghelp/breakpad）的固有取舍，本实现已尽量避免在崩溃路径使用堆/loader 锁来降低概率。
- **非严格全进程冻结**：冻结基于"一次线程快照 + 逐线程挂起"。能阻止快照中已存在线程继续前进，但**不能阻止快照之后新建的线程**——新线程不会进入线程计划、也不会被冻结。考虑到崩溃现场新建线程概率低、且线程计划不可变（新线程不会破坏已固化数据的一致性），本实现**刻意不做二次快照补挂起**，以避免拉长冻结窗口、增加上面"冻结期死锁"的概率。因此文档表述为"尽力冻结快照中线程"，而非"冻结所有线程"。
- **线程/模块上限**：线程计划上限 `kMaxThreads`（默认 1024）、模块上限 `kMaxModules`（默认 4096）；全内存 / 间接引用区域数受 4MB scratch 缓冲容量上限约束（见下"预分配内存"）。超出部分会被截断，dump 仍结构合法但可能不完整。**异常线程例外**：即使线程快照失败、或线程数超过 `kMaxThreads`，写 dump 时也会**显式保证异常线程（`ExceptionParam->ThreadId`）被加入线程计划**（必要时单独 `OpenThread` 并在计划已满时挤占一个非当前、非异常线程的槽位），从而 `ExceptionStream` 的 context 槽位始终指向正确的异常线程 context，不会指错。
- **仅完整支持 x64/x86**：ARM64 下 PEB/TEB 段寄存器读取不可用，模块与栈信息会退化。
- **文件句柄需为同步句柄**：内部用同步 `WriteFile`，请勿传入 `FILE_FLAG_OVERLAPPED` 打开的句柄。

## 预分配内存

本方案在崩溃路径上**不做任何显式堆/`VirtualAlloc` 分配**，所需缓冲全部是**编译期固定大小的静态全局数组**（位于 `.bss`，零初始化）。这是核心设计取舍——下面是清单与原因。

| 静态缓冲 | 大小 | 用途 |
|---|---|---|
| `g_ScratchBuffer` | **4 MB** | 多用途共享 scratch（见下复用说明） |
| `g_ThreadPlan[kMaxThreads]` | 1024 × 88 B ≈ **88 KB** | 冻结后固化的不可变"线程计划"（最多 1024 线程） |
| `g_KnownMemoryRanges[kMaxThreads+4096]` | 5120 × 16 B ≈ **80 KB** | 已规划区域表（栈/数据段），供间接扫描去重判重叠 |
| `g_ContextScratch` | `sizeof(CONTEXT)` ≈ **1.2 KB** | 取单个线程寄存器上下文的临时区 |
| 其余计数器/标志/API 表 | < 1 KB | — |
| **合计** | **≈ 4.2 MB** | 全部为 demand-zero，仅实际触达的页才占物理内存 |

**`g_ScratchBuffer`（4 MB）按阶段复用**（这些用途在时间上互不重叠，故共用一块以压低静态占用）：
- 阶段一 = `NtQuerySystemInformation` 进程/线程快照的接收缓冲（构建线程计划时一次性消费完）；
- 阶段二 = `MiniDumpWithFullMemory` 的内存区域计划：可容纳 `4MB / 16B = 262,144` 个区域；
- 阶段二' = 间接引用扫描计划：缓冲**对半分**，下半 2 MB 存范围（`2MB / 16B = 131,072` 个 4K 页 ≈ 最多 **512 MB** 被引用内存），上半 2 MB 作访问去重的开放寻址哈希集（`2MB / 8B = 262,144` 槽）。

**为什么这么做（设计动机）**：
1. **崩溃现场不能信任堆与 loader**：进程崩溃时堆可能已损坏、loader 锁可能被持有。任何 `malloc`/`new`/`HeapAlloc`/`LoadLibrary` 都可能死锁或二次崩溃。预分配静态内存让写 dump 全程零分配、零加载，最大化可靠性。
2. **`.bss` 零成本**：这些数组是零初始化全局，落在 `.bss`，**不增加二进制体积**（磁盘上只是个大小字段），运行期由操作系统按需 demand-zero 提交——没触达的页不占物理内存。所以"4.2 MB"是上限，常态远低于此。
3. **一致性需要"快照式"存储**：把线程计划/内存区域计划一次性固化到固定数组，是"描述符大小 == 实际字节"一致的前提（见一致性模型）。
4. **上限可调**：若目标进程线程/模块数或期望的间接内存量更大，可调 `kMaxThreads` / `kMaxModules` / `kScratchBufferSize` 重新编译，按需换取更大静态占用。

## 鲁棒性与性能评估

### 鲁棒性

机制细节见上文"设计约束"（无堆/无 loader、SEH 容错、一致性模型、并发串行化），此处只补充验证与退化行为：

- **退化而非崩溃**：PEB/LDR 损坏 → 模块表降级为空；线程快照失败 → 至少 dump 当前线程与异常线程；超上限 → 截断但结构合法；坏页 → 补零而非失败。
- **验证覆盖**：
  - `MiniDumpInprocHeapFailTest`：强制 `HeapAlloc`/`RtlAllocateHeap`/`VirtualAlloc` 等全部返回 `NULL` 时 dump 仍正常产出，证明崩溃路径无堆分配。
  - `MiniDumpInprocStressTest`：150+ 线程跑空指针写 / 栈溢出 / UAF / 堆破坏 / 数据段按引用收集等场景，产出可被 WinDbg 完整解析的 dump（异常、完整调用栈、全部线程、多层间接内存）。
- **残留风险**：见"已知残留风险与限制"。其中 `__fastfail` 类崩溃绕过所有进程内异常处理器（VEH/SEH/UnhandledExceptionFilter 均收不到），进程内无解。

### 性能
- **冻结窗口**：写 dump 期间其余线程被挂起，整体停顿 ≈ 采集 + 落盘耗时，与 dump 体积成正比（典型选择性 dump 数 MB，毫秒级到几十毫秒）。这与 `MiniDumpWriteDump`/breakpad 同量级。
- **句柄一次性预开**：冻结前一次性 `OpenThread`，避免冻结期间再取句柄表锁，降低死锁概率，也减少系统调用往返。
- **间接扫描已做工程优化**：
  - **去重哈希 O(1)**：访问过的页用开放寻址哈希集判重，避免多层扫描退化为 O(n²)；
  - **`VirtualQuery` 单条区域缓存**：聚簇指针落在同一区域时免重复系统调用（崩溃现场指针高度聚簇，命中率高）；
  - **整页一次读**：扫描已收集页时整页拷贝后在本地缓冲遍历，降低逐指针的 SEH 开销；
  - **崩溃线程子树优先**：预算紧张时优先收集与崩溃最相关的数据，避免无效扫描。
- **预算驱动**：选择性 dump 下 `MaxFileSize` 把数据段/间接内存逐层截断，既控体积也控 I/O 与扫描时间（full memory 不受此约束，见上文）。
- **零分配开销**：无 `malloc`/`free` 往返、无碎片，缓冲首次触达才提交物理页。
- **成本主项**：`MiniDumpWithFullMemory` 全量 `VirtualQuery` 遍历 + 落盘是最重的；选择性 dump（栈 + 按需间接）通常显著更轻。

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

`MiniDumpInprocStressTest` 以父/子进程模型逐场景验证稳定性：子进程拉起 150 个工作线程（每个在栈上挂一条 3 层指针链，专门喂给多层间接扫描），用**独立大栈的 dump 线程**写 dump（崩溃线程仅在过滤器里发信号 + 等待，从而即使栈溢出也能写出——这正是推荐的栈溢出处理范式），再触发真实崩溃：空指针写、栈溢出、释放后使用、堆元数据破坏；父进程随后解析 dump 校验 header、流集合并确认捕获了 100+ 线程。此外还有一个 `datasegs_indirect` 场景专门验证"数据段按引用收集"：进程持有一个 8MB 全局块，仅在崩溃线程栈上放一个指向其中某页的指针，dump 时**只带 `MiniDumpWithIndirectlyReferencedMemory`、不带 `MiniDumpWithDataSegs`**；父进程断言该被引用页的 magic 在 dump 中**存在**、而一个无人引用的远端页 magic **不存在**（证明全局块未被整段灌入，只按引用收了触达页）。运行示例：

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

// 无需显式初始化：库在模块加载时（全局构造）自动预解析所需 ntdll 例程。
// 若该预解析未完成，WriteMiniDumpInproc 会返回 FALSE（ERROR_NOT_READY），
// 崩溃路径绝不回退到 GetProcAddress 等 loader 调用。

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
    mei.ClientPointers = FALSE;   // 必须为 FALSE：本实现是进程内自 dump，
                                  // 传 TRUE 会被拒绝（返回 ERROR_INVALID_PARAMETER）。

    // 第 4 个参数是 dmp 文件大小软上限（字节），0 表示不限制。
    // 注意：MiniDumpWithFullMemory 会忽略该上限（保留全部内存，避免误丢线程栈）。
    (void)WriteMiniDumpInproc(hFile, MiniDumpNormal, &mei, 0);
    CloseHandle(hFile);
    return EXCEPTION_EXECUTE_HANDLER;
}
```

> 栈溢出场景请参考 `examples/inproc_stress_test.cpp`：从一个预留独立大栈的专用 dump 线程调用 `WriteMiniDumpInproc`，崩溃线程只在过滤器里投递异常信息并等待。
