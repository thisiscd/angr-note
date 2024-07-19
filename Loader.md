# Loader 
`cle.Loader` 表示整个被加载的二进制对象，加载并映射到整个内存空间。每个二进制对象都由处理其文件类型的加载器后端加载（cle.Backend 的子类）。例如，cle.ELF 用于加载 ELF 二进制文件。

```python
import angr, monkeyhex
proj = angr.Project('examples/fauxware/fauxware')
proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```

1. `loader.all_objects`： 获取 CLE 已加载的对象的完整列表
   ```python
   # All loaded objects
    >>> proj.loader.all_objects
    [<ELF Object fauxware, maps [0x400000:0x60105f]>,
    <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
    <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
    <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
    <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
    <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]
   ```
   其中，`ELFTLSObject` 用于提供线程本地存储支持的对象，`ExternObject`用于提供未解析的符号。
   - `proj.loader.shared_objects`: 从共享对象名称到对象的字典映射
   - `proj.loader.all_elf_objects`
   - `proj.loader.extern_object`: 用来提供未解析的导入和 angr 内部的地址
   - `proj.loader.kernel_object`: 用于为模拟系统调用提供地址
   - `proj.loader.find_object_containing(0x400000)`: 获取对给定地址的对象的引用
  
2. 这些对象提供了一些交互接口用于提取数据
   - obj = proj.loader.main_object
   - `obj.entry`： 对象的入口
   - `obj.min_addr, obj.max_addr`
   - `obj.segments` `obj.sections`: 检索此 ELF 的段和节
   - `obj.find_segment_containing(obj.entry)`
   - `obj.find_section_containing(obj.entry)`
   - `addr = obj.plt['strcmp']`: 获取一个符号（如 strcmp）在程序链接表（PLT）中的地址
   - `obj.reverse_plt[addr]`: 获取PLT地址中对应的符号
   - `obj.linked_base` `obj.mapped_base`: 显示对象的预链接基址以及 CLE 实际将其映射到内存的位置
  
3. Symbols and Relocations
    可以使用 CLE 处理符号。符号是可执行格式领域的基本概念，将名称映射到地址。
    从 CLE 获取符号的最简单方法是使用 `loader.find_symbol`
    ```python
    strcmp = proj.loader.find_symbol('strcmp')
    strcmp
    <Symbol "strcmp" in libc.so.6 at 0x1089cd0>
    ```