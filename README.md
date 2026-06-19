# MiniDumpInproc

Windows CMake 工程，提供进程内写 dump 的最小封装。

> **定位**：这是一个 **crash-path best-effort 的进程内 minidump writer**——不调用 `MiniDumpWriteDump`、无显式堆分配、不依赖 `dbghelp`、崩溃路径不走 loader/CRT 重路径。它在进程已部分损坏、且只能进程内自救（如被反作弊限制无法进程外 dump）时，**尽力**产出一个可打开、信息尽可能多的 dump，但**不承诺**在任意损坏程度下都成功或完整一致。若进程未受限、可接受外部进程，最可靠形态仍是 WerFault 式 out-of-process `MiniDumpWriteDump`。

封装签名：

```cpp
BOOL WriteMiniDumpInproc(
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,  // 可为 NULL；用户自定义流（见下）
    ULONG64 MaxFileSize);   // 硬上限；小于 4 MB（含 0）钳制到 4 MB
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
| **大小控制** | 原生支持 `MaxFileSize` 硬上限 + **优先级裁剪**（崩溃栈/主线程栈优先，其它栈和可选内存按预算裁剪） | 无大小上限参数；体积由 `DumpType` 决定，要么全要么无 |
| **间接引用内存** | **多层 BFS 指针扫描**（崩溃线程子树优先，去重哈希 + VirtualQuery 缓存） | `MiniDumpWithIndirectlyReferencedMemory` 为单层引用，且依赖堆分配 |
| **功能完整度** | 裁剪实现：`HandleData` / `TokenInformation` 等**有意不写**（见下） | **功能完整**：句柄、Token、回调扩展等全面支持 |
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

固定写入（与标志无关，始终产出）：`SystemInfoStream`、`MiscInfoStream`、`CommentStreamA`、`ModuleListStream`、`ThreadListStream` + 全部线程 `CONTEXT`；传入异常信息时附带 `ExceptionStream`。另：当通过 `SetMiniDumpInprocComment*` 设置过用户注释时，附带 `CommentStreamW`（见下）；当请求 `MiniDumpWithUnloadedModules` 且 ntdll 卸载环表非空时，附带 `UnloadedModuleListStream`（见下表）。

> **`CommentStreamA`（系统/进程内存与资源摘要）**：始终写入一段 ANSI 文本（四行），记录崩溃时的关键内存与资源指标，方便后续定位 OOM / 内存泄漏 / 句柄泄漏 / GDI-USER 泄漏 / 内核池泄漏，并附本次写 dump 的总耗时。**WinDbg 打开 dump 时会自动显示该 Comment**，无需额外命令；`MiniDumpInspect` 也会打印其文本。取值全程**零堆分配**、SEH 保护，查询失败则记为 `unavailable` / `n/a` 而不影响 dump。示例：
>
> ```text
> SysMem: Load=46% PhysTotal=130514MB PhysAvail=70302MB CommitTotal=149659MB CommitAvail=70099MB VirtTotal=134217727MB VirtAvail=134213403MB
> ProcMem: WorkingSet=8MB PeakWorkingSet=8MB PrivateCommit=30MB PeakCommit=30MB VirtSize=4324MB PeakVirtSize=4324MB PageFaults=2262
> ProcRes: PagedPool=62KB PeakPagedPool=62KB NonPagedPool=84KB PeakNonPagedPool=84KB Handles=51 PeakHandles=51 GDI=50 USER=40
> ProcTime: Elapsed=     11201us
> ```
>
> 各行来源与含义：
>
> - **`SysMem`** ← `GlobalMemoryStatusEx`（kernel32 静态导入）：`Load`=系统内存负载%、`Phys*`=物理内存总量/可用、`Commit*`=提交（页面文件）总量/可用、`Virt*`=本进程虚拟地址空间总量/可用。
> - **`ProcMem`** ← 预解析 `NtQueryInformationProcess(ProcessVmCounters → VM_COUNTERS_EX)`：`WorkingSet`/`PeakWorkingSet`、`PrivateCommit`（私有提交 = Private Bytes）/`PeakCommit`（峰值提交）、`VirtSize`/`PeakVirtSize`（虚拟大小及峰值）、`PageFaults`（缺页次数）。
> - **`ProcRes`** ← 内核池配额（同上 `VM_COUNTERS_EX`）+ 句柄数 + GDI/USER 对象数：`PagedPool`/`NonPagedPool`（及各自峰值，KB 粒度）反映内核对象占用的两类内核池；`Handles`/`PeakHandles` ← `NtQueryInformationProcess(ProcessHandleCount)`，峰值用于句柄泄漏定位；`GDI`/`USER` ← `user32!GetGuiResources`。
> - **`ProcTime`** ← `QueryPerformanceCounter`：`Elapsed`=本次 `WriteMiniDumpInproc` 的总耗时（微秒，右对齐定宽字段）。该字段在布局阶段以占位形式预留，并在**所有其它 stream 写完之后**回填真实耗时，因此 `CommentStreamA` 被**最后写入**（写入器用绝对 RVA seek，stream 物理顺序与写入顺序解耦），使耗时几乎覆盖整个 dump 过程，便于评估崩溃路径性能。
>
> **`CommentStreamW`（用户自定义注释，INI 形式）**：除自动摘要外，可在崩溃前通过两个导出函数附加任意诊断上下文，最终都写入同一个 **`CommentStreamW`**（宽字符流，WinDbg 打开时同样自动显示）：
>
> ```c
> typedef enum _COMMENT_STRING_OPER_TYPE {
>     CommentStringReplace = 0, // upsert 覆盖；value=NULL 时删除该 key 整行
>     CommentStringMerge   = 1, // 按 ';' token 去重追加（已存在则不变）；value=NULL 为空操作
>     CommentStringAppend  = 2, // 无条件 ';' 拼接（允许重复）；value=NULL 为空操作
> } COMMENT_STRING_OPER_TYPE;
>
> BOOL SetMiniDumpInprocCommentA(const char*    section, const char*    key, const char*    value, COMMENT_STRING_OPER_TYPE oper);
> BOOL SetMiniDumpInprocCommentW(const wchar_t* section, const wchar_t* key, const wchar_t* value, COMMENT_STRING_OPER_TYPE oper);
> ```
>
> - **A/W 统一落点**：`A` 版本按当前 ANSI 代码页（`CP_ACP`）将入参转为 UTF-16 后转交 `W` 版本，二者数据都进同一个 `CommentStreamW`；自动内存摘要仍走独立的 `CommentStreamA`，互不干扰。
> - **INI 文本累积**：内部用一块固定宽字符缓冲（`kCommentBufferWChars`，默认 4096 WCHAR）保存形如 `[Section]\nKey=Value\n…` 的 INI 文本，进程生命周期内持续累积，可分多次增量设置，并被之后的**每一次** dump 包含。
> - **操作语义**（针对单个 `Key`）：`REPLACE` 存在即覆盖、否则新增（`value=NULL` 删除该行）；`MERGE` 把旧值视作 `;` 分隔的 token 列表，新值不在其中才追加（去重）；`APPEND` 无条件用 `;` 追加（可重复）。`MERGE`/`APPEND` 传 `NULL` 为空操作。
> - **入参大小限制与归一化**：`section`/`key` 字符数上限 **64**，超过直接返回 `FALSE`（不截断）；`value` 字符数上限 **256**，超过**截断**。归一化后的 `value` 中，每个换行符替换为单个 `$`，每个 `;` 替换为全角 `；`（U+FF1B）；两种替换均为 1:1，存储后长度不超过 256 WCHAR，从而保证值始终位于单个 INI 行内，且不会与 `MERGE`/`APPEND` 使用的 `;` token 分隔符冲突。
> - **入参校验与鲁棒**：`section`/`key` 必须非空，否则返回 `FALSE`；缓冲放不下结果也返回 `FALSE`。并发 setter 用轻量自旋锁串行化，且对调用方指针做 SEH 保护。与本库其余部分一致，这些 setter 设计为**崩溃前**调用，不保证与正在进行的 `WriteMiniDumpInproc` 并发安全。
>
> 关于 `GDI`/`USER`：仅当进程**已加载 user32** 时采集——库在加载期用 `GetModuleHandleW`（**绝不** `LoadLibrary`）条件解析 `GetGuiResources` 指针，因此**不会给控制台/服务进程强加 user32 依赖**；非 GUI 进程显示 `GDI=n/a USER=n/a`。该调用跨入 win32k 子系统、有 SEH 保护，且在冻结其它线程**之前**采集以规避 GUI 锁死锁。`GetGuiResources` 自身**不做用户态堆分配**（由 `GdiUserHandleAllocTrace` demo 实测验证，见下"构建"），符合崩溃路径无堆分配的约束。

| 标志 | 支持程度 | 说明 |
|---|---|---|
| `MiniDumpNormal` | ✅ 裁剪完整 | 基础流 + 按硬上限优先级保留的线程栈窗口（`MemoryList`），优先保证崩溃线程与主线程 |
| `MiniDumpWithFullMemory` | ✅ 完整或失败 | 改写 `Memory64List`，dump 全部已提交可读区域；若完整 full-memory dump 超过 `MaxFileSize` 硬上限则失败，不静默截断 |
| `MiniDumpWithFullMemoryInfo` | ✅ 完整 | 写 `MemoryInfoList`（VirtualQuery 区域属性） |
| `MiniDumpWithThreadInfo` | ✅ 完整 | 写 `ThreadInfoList`（创建/内核/用户时间、起始地址等） |
| `MiniDumpWithProcessThreadData` | ✅ 同上 | 等价触发 `ThreadInfoList` |
| `MiniDumpWithDataSegs` | ✅ 完整 | **设置**=全量写可写 image 数据段（globals/statics），作为可裁剪层优先级 1，预算不足整体放弃；**不设**=数据段不再整段捕获，而是交给间接引用扫描"按需"收集（见下，适合超大全局块） |
| `MiniDumpWithIndirectlyReferencedMemory` | ✅ 增强 | **多层 BFS 指针扫描**（见下）；可裁剪层最低优先级，按剩余预算逐页截断。未设 `MiniDumpWithDataSegs` 时，可写数据段也作为扫描目标被"按引用"收集 |
| `MiniDumpIgnoreInaccessibleMemory` | ♾️ 始终生效 | 本实现**所有**内存区域（线程栈/数据段/间接引用/全内存）一律对不可读页补零、绝不因坏页失败；该标志因此**无论设不设都等效"已设"**，仅保留在 `header.Flags` |
| `MiniDumpScanMemory` | ⚠️ 忽略 | 不做模块引用标记，标志仅保留在 `header.Flags` |
| `MiniDumpWithUnloadedModules` | ✅ 按需写 | **设置**=从 ntdll 卸载模块环表写 `UnloadedModuleListStream`（让 WinDbg 能命名崩溃前刚卸载 DLL 的栈帧），无堆分配、`SafeCopyBytes` 全程保护、跳过空槽；**不设**=完全不读环表、不写该流 |
| `MiniDumpWithHandleData` | ❌ 不写 | 见"为什么不写 `HandleDataStream`" |
| `MiniDumpWithTokenInformation` | ❌ 不写 | 崩溃路径采集 Token 价值低、易触发危险调用，标志仅保留在 `header.Flags` |
| 其它未列出标志 | ⚠️ 忽略 | 不报错，按未实现处理，仅保留在 `header.Flags` |

> 约定：表中"忽略/不写"的标志传入后**不会导致失败**，只是不产生对应内容；`header.Flags` 仍如实记录调用方请求的原始标志位，便于分析端识别意图。

- **`MaxFileSize` 与优先级裁剪**：`MaxFileSize` 是硬上限（字节）；调用前先经 `NormalizeHardMaxFileSize` 归一化——小于 4 MB（含 0）一律按 **4 MB** 处理（当前实现**没有"0 = 不限制"语义**）。数据写入分两层：**固定层**必须能放入硬上限，否则直接失败；**可裁剪层**在剩余预算内按优先级填充，预算不够就裁剪/丢弃。

  **第一层 · 固定层（必写，放不下即 `ERROR_FILE_TOO_LARGE`）**：与 `DumpType` / 预算无关，是 dump 可打开、可分析的最小骨架。

  | 优先级 | 内容 | 说明 |
  |---|---|---|
  | 1 | Header + Stream Directory | 文件头与目录，最小结构 |
  | 2 | `SystemInfoStream` | CPU 架构、OS 版本 |
  | 3 | `MiscInfoStream` | 进程 ID 等 |
  | 4 | `ModuleListStream`（+ CodeView） | 还原符号必需 |
  | 5 | `ThreadListStream` + 全部线程 `CONTEXT` | 线程列表与寄存器上下文 |
  | 6 | `ExceptionStream` | 传入异常信息时写，指向异常线程 context |
  | 7 | `ThreadInfoList` / `MemoryInfoList` | 按 `DumpType` 标志触发 |

  **第二层 · 栈与可选内存（在剩余预算内按下表顺序填充，不足则裁剪/放弃）**：

  | 优先级 | 内容 | 裁剪行为 |
  |---|---|---|
  | 1 | **崩溃/异常线程栈窗口** | 最高优先；`STATUS_STACK_OVERFLOW` 且原始栈 ≤ 1 MB 时**完整保留**（放不下直接失败），> 1 MB 时只保留 live 窗口 |
  | 2 | **栈溢出高地址栈顶辅助窗口** | 仅 `STATUS_STACK_OVERFLOW` 且 > 1 MB：保留靠近 `StackBase` 的窗口，用于看递归进入前的调用来源 |
  | 3 | **主线程栈窗口** | 次高优先，保证主线程可回溯 |
  | 4 | **其它线程栈窗口** | best-effort，默认每个裁到约 1 MB，预算不足按顺序丢弃 |
  | 5 | `MiniDumpWithDataSegs` 可写数据段 | 预算不足时**整体放弃** |
  | 6 | `UserStreamParam` 用户自定义流 | 逐个 all-or-nothing，按数组顺序纳入直到某个放不下即停止（见下"用户自定义流"） |
  | 7 | `MiniDumpWithIndirectlyReferencedMemory` 间接引用内存 | **最低优先级**，按剩余预算逐页截断（其内部又以"崩溃线程引用子树优先于其它线程子树"细分，见下"多层间接引用扫描"） |

  一句话优先级链：

  ```text
  Header/Directory/SystemInfo/MiscInfo/ModuleList/ThreadList+Context/Exception（固定，放不下即失败）
    → 崩溃线程栈 → 栈溢出高地址栈顶窗口 → 主线程栈 → 其它线程栈
    → DataSegs → 用户自定义流 → 间接引用内存（崩溃线程子树 → 其它线程子树）
  ```

  - **崩溃线程 == 主线程时不重复记录**：主线程栈仅在 `mainIndex != exceptionIndex` 时才单独纳入；崩溃就在主线程时该步直接跳过。即便未跳过，`IncludePrimaryStack` 对已标记 `IncludeStack` 的线程也会直接返回，因此 `MemoryList` 不会出现两条相同栈范围。其它线程循环也会跳过 `exceptionIndex` / `mainIndex`。
  - **栈裁剪**：线程栈不再整段强制写入；默认每个线程栈窗口限制在约 1 MB 内（`kMaxCapturedStackBytes`）。`STATUS_STACK_OVERFLOW` 会先看异常线程原始栈空间（`kStackOverflowFullStackThreshold` = 1 MB）：若不超过 1 MB，则完整记录该栈（硬上限放不下则失败返回 `ERROR_FILE_TOO_LARGE`）；若超过 1 MB，则用确定性双窗口——从异常 `SP/RSP` 起保留约 512 KB 的 live unwind 窗口（`kStackOverflowLiveStackBytes`），并额外保留靠近 `StackBase` 的高地址栈顶约 512 KB（`kStackOverflowHighStackBytes`），用来观察递归进入前的调用来源；中间重复递归帧丢弃，避免 12 MB 这类大栈直接撑爆 dump。
  - **`MiniDumpWithFullMemory` 硬上限**：full memory dump 不走上面的栈裁剪/优先级，保持"完整或失败"语义、不按地址顺序截断。若完整的已提交可读区域、描述符和固定层总量超过 `MaxFileSize` 硬上限，返回 `ERROR_FILE_TOO_LARGE`。
  - **如何让 FullMemory"不限制大小"**：当前实现下 FullMemory 仍受硬上限约束，且 `MaxFileSize = 0` 会被钳到 4 MB（不是"不限制"）。若希望事实上不限制，**直接传一个远大于进程已提交内存的超大值**即可，例如 `1ULL * 1024 * 1024 * 1024 * 1024`（1 TB）；FullMemory 用 64 位 `Memory64List`，预算算术全程 64 位、不受选择性 dump 的 4 GB RVA 限制，传超大值是安全的。
  - **格式硬上限（4 GB）**：选择性内存 dump（非 `MiniDumpWithFullMemory`）的 `MemoryList` 用 32 位 RVA 寻址。内部把有效预算上限设为略小于 4 GB（`kSelectedDumpRvaLimit`）；若最终布局仍会超过 32 位 RVA 或 `MaxFileSize` 硬上限，直接失败返回 `ERROR_FILE_TOO_LARGE`，不产出 RVA 静默截断的损坏 dump。

- **用户自定义流（`UserStreamParam`）**：与 `MiniDumpWriteDump` 同形的 `PMINIDUMP_USER_STREAM_INFORMATION`，可写入应用自定义数据（构建号、配置、业务状态等）。每个 `MINIDUMP_USER_STREAM` 以其 `Type` 作为 stream 类型、`Buffer`/`BufferSize` 原样写入。要点：
  - **上限 16 个**（`kMaxUserStreams`），超出忽略；`Buffer == NULL` 或 `BufferSize == 0` 的条目跳过。
  - **优先级高于间接引用内存、低于数据段**：在剩余预算内按数组顺序逐个 all-or-nothing 纳入，遇到第一个放不下即停止（保证纳入的是确定性前缀），因此**也受 `MaxFileSize` 约束**。FullMemory 模式下在完整内存集之外按硬上限纳入。
  - **零堆 + 鲁棒**：调用方结构/数组在 SEH 保护下拷贝校验，缓冲在写入时读取；不可读缓冲补零而非失败。`Type` 与内置 stream 冲突的责任在调用方（与 `MiniDumpWriteDump` 一致）。
  - 写入时机：用户流字节排布在线程 context 之后、内存字节之前；其耗时计入 `CommentStreamA` 的 `ProcTime`。

- **多层间接引用扫描**：间接内存采用按层 BFS。第 1 层 = 线程栈上指针指向的 4K 可读页；第 2/3 层 = 从已收集页里再扫出的指针所指向的页（深度上限 `kIndirectMaxScanLayers`，默认 3，相关性随层数衰减）。优先级：**崩溃/异常线程的整棵引用子树（第 1→2→3 层）** 先于其它线程的子树收集，从而在预算紧张时优先保留与崩溃最相关的数据。去重用 scratch 缓冲上半区的开放寻址哈希集（O(1)，避免多层后退化为 O(n²)），并对 `VirtualQuery` 做单条区域缓存以降低聚簇指针的查询开销。收集总量受 `MaxFileSize` 预算与缓冲容量共同约束。

  扫描目标的取舍：**只读 image 页**（代码 `.text`、常量 `.rdata`）始终排除——它们能从模块文件还原，不值得占预算；**普通可读非镜像内存**（堆、私有、映射）一律可收；**可写 image 数据段**（全局/静态变量）是否参与取决于 `MiniDumpWithDataSegs`：
  - 未设 `MiniDumpWithDataSegs`：数据段**当作普通堆**对待，只收被指针链真正触达的 4K 页，并继续向下做多层扩散。对"全局数据块非常大"的工程尤其友好——不再整段灌入，只保留与崩溃相关的部分，受 `MaxFileSize` 预算约束。
  - 已设 `MiniDumpWithDataSegs`：数据段已整段全量捕获，并被纳入 known-range；间接扫描命中同一页时按重叠去重跳过，**不会重复收集**。

- 不使用 STL、CRT 容器或显式堆分配；模块、线程和内存区域通过遍历 PEB / 预解析的 `NtQuerySystemInformation` / `VirtualQuery` 统计并流式写入。
- **一致性模型**：进入 `WriteMiniDumpInproc` 后会先逐线程 `SuspendThread` **尽力冻结快照中的其余线程**（句柄在冻结前一次性打开，避免冻结期间再取句柄表锁），并只做**一次**线程快照，固化成不可变的“线程计划”（TEB、栈范围、时间等）。之后的与线程相关的 stream（ThreadList、线程 context、ThreadInfoList、栈 MemoryList、间接引用扫描）都只读这份计划；`MiniDumpWithFullMemory` 的内存区域也在一次 `VirtualQuery` 遍历里固化成固定列表，描述符与字节流严格一致。
  - **栈/线程 context 一致**：线程 context 直接来自已冻结的线程，与采集到的栈字节在同一冻结现场，回栈一致。例外：若使用专用 dump 线程范式（崩溃线程投递 `EXCEPTION_POINTERS` 给 dump 线程），异常线程的 context 来自崩溃发生时刻、其栈字节来自之后的冻结时刻，二者不是严格同一瞬间（实践中崩溃线程在投递后等待、不再前进，通常仍一致）。
  - **`MiniDumpWithDataSegs` 一致性较弱**：选择性 dump 里的可写数据段在计数 / 写描述符 / 写字节三个阶段分别重走 `VirtualQuery`（未像 full memory 那样固化成固定列表）。其余线程已冻结时地址空间通常稳定，但严格来说这部分不享有“描述符与字节流绝对一致”的保证（后续可优化为固化计划）。
- **并发崩溃串行化**：通过 `InterlockedCompareExchange` 单入口保护，多个线程同时崩溃时只有第一个写 dump，其余返回 `FALSE`（`ERROR_BUSY`），避免共享静态缓冲区被竞争。
- **初始化（强依赖加载期预解析，崩溃路径绝不走 loader）**：库在模块加载时（静态初始化阶段，`AutoInitInprocApis` 全局构造）自动预解析 `ntdll` 导出（`RtlGetVersion` / `NtQueryInformationThread` / `NtQuerySystemInformation` / `NtQueryInformationProcess`）。崩溃路径**绝不** lazy 调用 `GetModuleHandleW` / `GetProcAddress`（这些会取 loader 锁，崩溃现场可能已被持有或损坏）。若由于异常的初始化顺序导致加载期预解析未完成，`WriteMiniDumpInproc` 会直接失败返回 `FALSE`（`ERROR_NOT_READY`），而不是在崩溃路径触碰 loader。
  - **可选的显式预解析 `ResolveInprocApis()`**：除自动加载期初始化外，库还**导出**一个幂等的 `ResolveInprocApis()`（声明在 `minidump_inproc.h`）。调用它**非必需**——它只是让上述预解析在一个**确定的时机**发生：跨 translation unit / DLL 的全局构造顺序是未定义的，若你自己的全局/静态初始化依赖本库已就绪，可在其中**主动先调用** `ResolveInprocApis()` 以消除该顺序依赖。该函数内部用 `g_ApisInitialized` 标志判重，实际解析只执行一次，可重复、多线程安全调用，且只走 `GetModuleHandle` / `GetProcAddress`、**绝不** `LoadLibrary`。
- **内存复用**：进程信息快照缓冲、全内存范围表、间接引用范围表/哈希集**复用同一块 scratch 缓冲**（这些用途在时间上互不重叠），整体静态占用显著下降。


- 文件由调用方打开并传入 `hFile`，函数内不构造路径、不创建文件、不分配大缓冲区。
- MSVC 构建下用 SEH 包住关键内存读取和写 dump 主流程，坏页会尽量以零页补齐。
- **逐 stream 容错（内存严重破坏时不彻底失败）**：除"文件头 + stream 目录"这一最小结构外，每个 stream 的采集与写入都在**独立的 SEH 保护**下进行。如果在内存严重破坏的情况下某个 stream 采集时触发**访问违例（SEH fault）**，该 stream 会被**跳过**（其预排布的区域保持零填充），dump 继续写出其余所有 stream，而不是整体失败。计数阶段（模块/内存信息/栈/数据段/间接引用）的失败同样降级为"该部分为空"而非中止。
  - **当前精确语义**：SEH 访问违例会按 stream 跳过；支持三态返回的 stream 可显式返回 `Skip` 而不中止；普通 stream 写函数返回 `FALSE` 仍按文件 I/O 或不可恢复写入失败处理并中止。这样即使在受损进程里，也能尽量产出一个"残缺但可打开、信息尽可能多"的 dump，同时避免在文件句柄无效、磁盘写满等场景继续写坏文件。

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
| `g_ThreadPlan[kMaxThreads]` | 1024 × 约 128 B ≈ **128 KB** | 冻结后固化的不可变"线程计划"（最多 1024 线程） |
| `g_KnownMemoryRanges[kMaxThreads+4096]` | 5120 × 16 B ≈ **80 KB** | 已规划区域表（栈/数据段），供间接扫描去重判重叠 |
| `g_ContextScratch` | `sizeof(CONTEXT)` ≈ **1.2 KB** | 取单个线程寄存器上下文的临时区 |
| `g_CommentBuffer` | **1 KB** | `CommentStreamA` 的系统/进程内存摘要 ANSI 文本 |
| `g_CommentBufferW` | **8 KB** | `CommentStreamW` 的用户自定义 INI 注释宽字符文本（4096 WCHAR） |
| 其余计数器/标志/API 表 | < 1 KB | — |
| **合计** | **≈ 4.3 MB** | 全部为 demand-zero，仅实际触达的页才占物理内存 |

**`g_ScratchBuffer`（4 MB）按阶段复用**（这些用途在时间上互不重叠，故共用一块以压低静态占用）：
- 阶段一 = `NtQuerySystemInformation` 进程/线程快照的接收缓冲（构建线程计划时一次性消费完）；
- 阶段二 = `MiniDumpWithFullMemory` 的内存区域计划：可容纳 `4MB / 16B = 262,144` 个区域；
- 阶段二' = 间接引用扫描计划：缓冲**对半分**，下半 2 MB 存范围（`2MB / 16B = 131,072` 个 4K 页 ≈ 最多 **512 MB** 被引用内存），上半 2 MB 作访问去重的开放寻址哈希集（`2MB / 8B = 262,144` 槽）。

**为什么这么做（设计动机）**：
1. **崩溃现场不能信任堆与 loader**：进程崩溃时堆可能已损坏、loader 锁可能被持有。任何 `malloc`/`new`/`HeapAlloc`/`LoadLibrary` 都可能死锁或二次崩溃。预分配静态内存让写 dump 全程零分配、零加载，最大化可靠性。
2. **`.bss` 零成本**：这些数组是零初始化全局，落在 `.bss`，**不增加二进制体积**（磁盘上只是个大小字段），运行期由操作系统按需 demand-zero 提交——没触达的页不占物理内存。所以"4.3 MB"是上限，常态远低于此。
3. **一致性需要"快照式"存储**：把线程计划/内存区域计划一次性固化到固定数组，是"描述符大小 == 实际字节"一致的前提（见一致性模型）。
4. **上限可调**：若目标进程线程/模块数或期望的间接内存量更大，可调 `kMaxThreads` / `kMaxModules` / `kScratchBufferSize` 重新编译，按需换取更大静态占用。

## 鲁棒性与性能评估

### 鲁棒性

机制细节见上文"设计约束"（无堆/无 loader、SEH 容错、一致性模型、并发串行化），此处只补充验证与退化行为：

- **退化而非崩溃**：PEB/LDR 损坏 → 模块表降级为空；线程快照失败 → 至少 dump 当前线程与异常线程；线程/模块/范围表容量上限 → 结构合法但信息可能不完整；`MaxFileSize` 硬上限不足 → 失败返回 `ERROR_FILE_TOO_LARGE`；坏页 → 补零而非失败。
- **验证覆盖**：
  - `MiniDumpInprocHeapFailTest`：强制 `HeapAlloc`/`RtlAllocateHeap`/`VirtualAlloc` 等全部返回 `NULL` 时 dump 仍正常产出，证明崩溃路径无堆分配。
  - `MiniDumpInprocStressTest`：150+ 线程跑空指针写 / 栈溢出 / UAF / 堆破坏 / 数据段按引用收集等场景，产出可被 WinDbg 解析的 dump（异常、线程列表/上下文、按预算裁剪的关键栈窗口、多层间接内存）。
- **残留风险**：见"已知残留风险与限制"。其中 `__fastfail` 类崩溃绕过所有进程内异常处理器（VEH/SEH/UnhandledExceptionFilter 均收不到），进程内无解。

### 性能
- **冻结窗口**：写 dump 期间其余线程被挂起，整体停顿 ≈ 采集 + 落盘耗时，与 dump 体积成正比（典型选择性 dump 数 MB，毫秒级到几十毫秒）。这与 `MiniDumpWriteDump`/breakpad 同量级。
- **句柄一次性预开**：冻结前一次性 `OpenThread`，避免冻结期间再取句柄表锁，降低死锁概率，也减少系统调用往返。
- **间接扫描已做工程优化**：
  - **去重哈希 O(1)**：访问过的页用开放寻址哈希集判重，避免多层扫描退化为 O(n²)；
  - **`VirtualQuery` 单条区域缓存**：聚簇指针落在同一区域时免重复系统调用（崩溃现场指针高度聚簇，命中率高）；
  - **整页一次读**：扫描已收集页时整页拷贝后在本地缓冲遍历，降低逐指针的 SEH 开销；
  - **崩溃线程子树优先**：预算紧张时优先收集与崩溃最相关的数据，避免无效扫描。
- **预算驱动**：选择性 dump 下 `MaxFileSize` 硬上限会先裁剪栈窗口，再裁剪数据段/间接内存，既控体积也控 I/O 与扫描时间；full memory 超过硬上限则失败。
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
cd <项目根目录>
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
- `MiniDumpInspect`：轻量 dump 解读工具，打印 header、stream 类型/大小和关键统计信息（含 `CommentStreamA` 的系统/进程内存摘要文本）
- `MiniDumpOverflowStackExt.dll`：WinDbg 扩展，提供 `!show_overflow_stack` 自动展示 `STATUS_STACK_OVERFLOW` 的完整栈/双窗口栈

Detours 相关 demo 默认关闭，避免生产/干净环境因 submodule 未初始化而构建失败。需要时显式开启：

```powershell
cmake -S . -B build -A x64 -DMINIDUMP_INPROC_BUILD_DETOURS_DEMO=ON
```

开启后额外生成：

- `MiniDumpWriteDumpAllocTrace`：基于 `third_party/Detours` 的 `MiniDumpWriteDump` 内存分配跟踪 demo
- `MiniDumpInprocHeapFailTest`：基于 Detours 将 `HeapAlloc` / `RtlAllocateHeap` / `VirtualAlloc` 等强制返回 `NULL`，验证 `WriteMiniDumpInproc` 的无堆分配路径
- `GdiUserHandleAllocTrace`：演示 GDI/USER 句柄计数的获取，并基于 Detours 跟踪 `user32!GetGuiResources` 是否触发用户态堆分配的 Win32 demo（见下）


`MiniDumpWriteDumpAllocTrace` 会 hook `HeapCreate` / `HeapAlloc` / `HeapReAlloc` / `HeapFree` / `HeapDestroy` / `VirtualAlloc` / `VirtualFree`，调用系统 `MiniDumpWriteDump` 后输出：新建 heap、落在新建 heap 上的分配事件、其他 heap 事件、VirtualAlloc 计数。运行示例：

```powershell
cd build\Release
.\MiniDumpWriteDumpAllocTrace.exe trace_test.dmp
```

`MiniDumpInprocHeapFailTest` 会覆盖以下极限场景：`HeapAlloc` 返回 `NULL`、`HeapReAlloc` 返回 `NULL`、`RtlAllocateHeap` / `RtlReAllocateHeap` 返回 `NULL`、`HeapCreate` / `RtlCreateHeap` 返回 `NULL`、`VirtualAlloc` 返回 `NULL`，以及包含 `MiniDumpWithIndirectlyReferencedMemory` 的富标志组合 dump，验证整条路径无任何 Heap/Virtual 分配。运行示例：


```powershell
cd build\Release
.\MiniDumpInprocHeapFailTest.exe
```

`GdiUserHandleAllocTrace` 演示 GDI/USER 句柄计数的获取方式，并验证采集这些计数的 `user32!GetGuiResources` 是否在用户态分配堆。它先创建一批真实 GDI 对象（DC / pen / brush / font / bitmap / region）与 USER 对象（隐藏窗口 / 菜单 / 图标）让计数明显变化，再用 Detours hook `HeapAlloc` / `HeapReAlloc` / `RtlAllocateHeap` / `RtlReAllocateHeap` / `VirtualAlloc`，并按"线程 + 时间窗口"过滤，精确统计**单次 `GetGuiResources` 调用期间本线程**的分配次数（排除后台线程噪声）。实测每次调用的分配计数均为 0，证明 `GetGuiResources` **不做用户态堆分配**，因此可安全用于崩溃路径的 `CommentStreamA`。运行示例：

```powershell
cd build\Release
.\GdiUserHandleAllocTrace.exe
```

`MiniDumpInprocStressTest` 以父/子进程模型逐场景验证稳定性：子进程拉起 150 个工作线程（每个在栈上挂一条 3 层指针链，专门喂给多层间接扫描），用**独立大栈的 dump 线程**写 dump（崩溃线程仅在过滤器里发信号 + 等待，从而即使栈溢出也能写出——这正是推荐的栈溢出处理范式），再触发真实崩溃：空指针写、4 种保留栈大小的栈溢出（256KB / 1MB / 2MB / 4MB）、释放后使用、堆元数据破坏。父进程随后解析 dump 校验 header、流集合并确认捕获了 100+ 线程。此外还覆盖：

- `datasegs_indirect`：验证"数据段按引用收集"。进程持有一个 8MB 全局块，仅在崩溃线程栈上放一个指向其中某页的指针，dump 时**只带 `MiniDumpWithIndirectlyReferencedMemory`、不带 `MiniDumpWithDataSegs`**；父进程断言该被引用页的 magic 在 dump 中**存在**、而一个无人引用的远端页 magic **不存在**。
- `indirect_object_graph`：验证多层对象图间接引用。崩溃栈只保留 root 指针，root -> child -> grandchild 三页对象必须都被多层扫描展开捕获。
- `type_*` 场景：覆盖 `MiniDumpNormal`、`MiniDumpWithThreadInfo` / `MiniDumpWithProcessThreadData`、`MiniDumpWithFullMemoryInfo`、`MiniDumpWithDataSegs`、`MiniDumpWithIndirectlyReferencedMemory`、`MiniDumpWithFullMemory` 等组合。

> 构建说明：`MiniDumpInprocStressTest` 作为调试/验证 demo，CMake 对其**关闭优化**（`/Od /Ob0 /Oy-`，在所有配置生效），以便在 Release / RelWithDebInfo 产出的 dump 里用 WinDbg `dv` 正常查看栈上局部变量（例如核对 `indirect_object_graph` 的 root/child/grandchild 指针）。优化开启时编译器会把这些变量放进寄存器或直接消除，`dv` 将看不到它们的值。该设置只作用于这一个 demo target，库 `MiniDumpInproc` 与其它目标不受影响。

运行示例：

```powershell
cd build\Release
.\MiniDumpInprocStressTest.exe
```

> 说明：堆元数据破坏在现代 Windows 上通常走 `__fastfail` 快速失败，**绕过所有进程内异常处理器**（VEH/SEH/UnhandledExceptionFilter 均收不到），因此这类崩溃在进程内无法写 dump——这是进程内方案的根本限制，压测里以 `INFO` 标记而非失败。

`MiniDumpInspect` 用于快速查看 dump 结构：

```powershell
cd build\Release
.\MiniDumpInspect.exe .\inproc_stress_stack_overflow_4m.dmp
```

### 用 WinDbg 扩展展示栈溢出逻辑调用栈

`STATUS_STACK_OVERFLOW` 且原始栈空间大于 1 MB 时，dump 会保留两段栈：异常 `SP/RSP` 附近的 live unwind 窗口，以及靠近 `StackBase` 的高地址栈顶窗口。由于中间栈帧被故意丢弃，WinDbg 原生 `k/kb/kp` 通常只能从当前 `RSP` 连续回溯 live 窗口；本工程提供 `MiniDumpOverflowStackExt.dll`，用 `!show_overflow_stack` 自动把两段窗口合成为更接近真实逻辑的栈：

```text
.load <项目根目录>\build\RelWithDebInfo\MiniDumpOverflowStackExt.dll
!show_overflow_stack
```

输出类似 `kn`，每帧包含序号、`Child-SP`、`RetAddr`、`module!symbol+0xNN` 和源码位置：

```text
 # Child-SP          RetAddr           Call Site [Source]
00 0000009c`76613310 00007ff7`064ab367 MiniDumpInprocStressTest!__chkstk+0x37 [...\chkstk.asm @ 108]
01 0000009c`76613328 00007ff7`064a2e6e MiniDumpInprocStressTest!`anonymous namespace'::RecurseUntilStackOverflow+0xd [...\inproc_stress_test.cpp @ 171]
02 0000009c`76613330 00007ff7`064a2ec1 MiniDumpInprocStressTest!`anonymous namespace'::RecurseUntilStackOverflow+0x60 [...\inproc_stress_test.cpp @ 175]
... (N repeated frames in M cycles) ...
... <0x... bytes of middle stack intentionally omitted> ...
   MiniDumpInprocStressTest!`anonymous namespace'::StackOverflowThreadProc+0x1d [...\inproc_stress_test.cpp @ 183]
   KERNEL32!BaseThreadInitThunk+0x16
   ntdll!RtlUserThreadStart+0x2b
```

说明：

- 对 `256 KB / 1 MB` 这类完整记录的栈，命令扫描 `SP/RSP` 到 `StackBase` 的完整窗口；对 `2 MB` 或更大的裁剪栈，扫描 live 窗口 + 高地址栈顶窗口，并自动过滤陈旧的 thread-start 伪栈。
- **重复递归帧折叠**：自动识别周期为 1~4 的重复帧块（普通递归周期 1，优化后常见的双调用点交替递归周期 2），折叠为 `... (N repeated frames in M cycles) ...`，仅保留首尾各一个完整周期。
- `Child-SP` / `RetAddr` 与原生 `kn` 对齐（`hi`lo` 反引号格式）。**源码行解析与符号在同一地址进行**，与 `kn` 一致：帧 0（崩溃 IP，不是返回地址）用精确地址（如 `__chkstk` 显示 `@ 109`），其余返回地址帧用 `retAddr-1`（call 指令所在行，如 `@ 171/175`）。注：返回地址帧的符号偏移按 `retAddr-1` 标注到 call 指令（如 `+0xd`），比 `kn` 显示的返回点偏移（`+0xe`）小 1，但行号一致。
- 输出使用 DML 可点击链接（命令里的地址统一用 `hi`lo` 反引号完整地址，避免 `0x...` 被当成 32 位触发 Range error）：
  - 帧序号 → `dps <Child-SP> L10`，查看该帧栈区域。注意：原生 `k` 的帧号点击是 `.frame 0n<idx>;dv /t /v`，依赖 WinDbg 自身的 unwind 帧表；本命令的帧是扫描栈内存合成的、不在该帧表里，`.frame` 无法选中（`.frame /r <地址>` 接收的是帧号而非地址，会报 Range error），因此退化为 `dps` 展示该帧栈区域。
  - `Call Site`（符号）→ 反汇编该返回地址附近指令；
  - `Source` → `lsa <retAddr-1>`，跳转到对应源码行。
- 可选参数：
  - `live=<bytes>` / `high=<bytes>`：调整 > 1MB 栈的 live / 高地址窗口大小（默认 512KB / 512KB，支持 `k`/`m` 后缀）。
  - `shadow[=<bytes>]`：在 `RetAddr` 与 `Call Site` 之间额外插入一列 **Shadow**（每帧的栈槽地址，可点开对该帧的影子栈窗口执行 `dps`；默认 32 字节）。
  - `noecxr`：不自动执行 `.ecxr`。

> 注意：命令通过扫描 dump 里保留的栈内存窗口合成逻辑栈。被裁剪的中间帧没有真实 unwind 上下文，因此帧数会比原生 `k` 多（每个递归层的多个返回地址槽都会被列出），也无法可靠还原 `kp` 的参数列表；`Child-SP/RetAddr/符号/源码行/影子栈` 均可正确展示。


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
// 可选：若担心跨 cpp/DLL 的全局初始化顺序，可在自己的初始化里先调用
// ResolveInprocApis()（幂等、可重复调用）以确保预解析在确定时机完成。

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

    // 第 4 个参数 UserStreamParam 为用户自定义流（不需要时传 nullptr）。
    // 最后一个参数是 dmp 文件大小硬上限（字节）；小于 4 MB（含 0）按 4 MB 处理。
    // 注意：MiniDumpWithFullMemory 超过硬上限会失败，不会静默截断。
    (void)WriteMiniDumpInproc(hFile, MiniDumpNormal, &mei, nullptr, 0);
    CloseHandle(hFile);
    return EXCEPTION_EXECUTE_HANDLER;
}
```

> 栈溢出场景请参考 `examples/inproc_stress_test.cpp`：从一个预留独立大栈的专用 dump 线程调用 `WriteMiniDumpInproc`，崩溃线程只在过滤器里投递异常信息并等待。
