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
    可以使用 CLE 处理符号。符号是可执行文件格式中的一个基本概念，上将一个名字映射到一个地址。
    - Symbol 对象属性：
      - name：符号的名称
      - owner：符号所属的对象（通常是某个共享库）
      - address：符号的地址

    从 CLE 获取符号的最简单方法是使用 `loader.find_symbol`
    ```python
    strcmp = proj.loader.find_symbol('strcmp')
    strcmp
    <Symbol "strcmp" in libc.so.6 at 0x1089cd0>
    
    # On Loader, the method is find_symbol because it performs a search operation to find the symbol.
    # On an individual object, the method is get_symbol because there can only be one symbol with a given name.
    main_strcmp = proj.loader.main_object.get_symbol('strcmp')
    ```

    - 符号地址:
      - rebased_addr：相对于加载基址的重定位后的地址。
      - linked_addr：在链接时定义的地址。
      - relative_addr：相对于所属对象基址的相对地址。

4. Loading options
   - backend - which backend to use, as either a class or a name
   - base_addr - a base address to use
   - entry_point - an entry point to use
   - arch - the name of an architecture to use
   
   details: [CLE documentation](https://api.angr.io/projects/cle/en/latest/api/index.html)

5. Symbolic Function Summaries
   默认情况下，Project 使用 symboilc summaries ( `angr.SIM_PROCEDURES` )来替换对库函数的外部调用 - 模仿库函数对 state 影响的 Python 函数。执行 SimProcedure 而不是从系统加载的实际库函数可以使分析变得更容易处理，但代价是一些潜在的不准确。
   - 如果 `auto_load_libs` 为 True（这是默认值），则执行真正的库函数。
   - 如果 `auto_load_libs` 为 False，Project 会将它们解析为名为 `ReturnUnconstrained` 的通用“stub” SimProcedure：每次调用时都会返回一个唯一的不受约束的符号值。
   - 如果 `use_sim_procedures` （ `angr.Project` 的参数 ）为 False （默认为True），则只有extern对象提供的符号将被 'stub' `ReturnUnconstrained` 替换，它除了返回一个符号值之外什么也不做。

angr 用 Python summaries 替换库代码的机制称为挂钩。在执行模拟时，angr 在每一步都会检查当前地址是否已被挂钩，如果是，则运行挂钩而不是该地址处的二进制代码。执行此操作的 API 是 proj.hook(addr, hook)，其中 hook 是 SimProcedure 实例。可以使用 .is_hooked、.unhook 和 .hooked_by 管理 hook。

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)
```