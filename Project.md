## `init` 方法

angr.Project 类的 __init__ 方法负责初始化一个 Project 对象，主要工作包括加载二进制文件、确定其 CPU 架构、设置默认分析模式、配置各种选项和属性、并执行一些特定于操作系统的设置。以下是 __init__ 方法的作用：

1. 加载二进制文件：
如果 thing 是一个 cle.Loader 对象，直接使用它。
如果 thing 是一个 cle.Backend 对象，使用它创建一个 cle.Loader。
如果 thing 是一个文件流，读取二进制数据并创建一个 cle.Loader。
否则，假设 thing 是一个文件路径，检查文件是否存在并加载二进制文件。

2. 确定 CPU 架构：
如果 arch 是一个字符串，使用 archinfo.arch_from_id 方法将其转换为 archinfo.Arch 对象。
如果 arch 是一个 archinfo.Arch 对象，直接使用它。
如果未提供 arch，使用 cle.Loader 自动检测的架构。

3. 设置默认值和属性：
设置默认的分析模式 (default_analysis_mode) 和要忽略的函数列表 (ignore_functions)，程序的入口点。
设置用于存储和加载项目的函数 (store_function 和 load_function)，默认使用 pickling 和 unpickling 等等

4. 确定guest OS (SimOS)：
如果 simos 是一个 SimOS 类，使用它创建一个 simos 实例。
如果 simos 是一个字符串，使用 os_mapping 获取相应的 SimOS 类并实例化。
如果未提供 simos，使用 cle.Loader 自动检测的操作系统并实例化相应的 SimOS。

5. Set up the project's hubs:
    - AngrObjectFactory 对象: 有几个方便的构造函数，用于经常使用的常见对象
    - analyses: 内置了一些分析方法，用于提取程序信息
    - KnowledgeBase 对象

6. 注册库函数的模拟过程：
如果目标架构支持 JNI 库，使用 simos 的本地架构注册模拟过程。
​ 根据库函数适当地注册 simprocedures。调用了内部函数 `_register_object`，这个函数将尽可能的将程序中的库函数与angr库中的实现的符号摘要替换掉，即设置 Hooking，这些angr实现的函数摘要高效地模拟库函数对状态的影响

1. 运行操作系统特定的配置：
调用 simos 的 configure_project 方法，执行操作系统特定的项目配置。