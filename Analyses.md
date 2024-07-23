## Built-in Analyses

- CFGFast: 快速构建程序的控制流程图
- CFGEmulated：构建准确的程序控制流程图
- VFG：对程序的每个函数执行 VSA，创建数据流图并检测堆栈变量

### 控制流图恢复

CFG 是一个以基本块为节点、以跳跃/调用/返回/等为边的图。
angr 恢复控制流图，包括函数边界的恢复，以及间接跳转和其他有用元数据的推理。在angr中，可以生成两种类型的CFG：静态CFG（CFGFast）和动态CFG（CFGEmulated）。
CFGFast 使用静态分析来生成 CFG。它的速度明显更快，但理论上受到某些控制流转换只能在运行时解决的限制。
CFGEmulated 使用符号执行来获取 CFG。虽然理论上它更准确，但速度也慢得多。由于仿真准确性问题（系统调用、缺少硬件功能等），它通常也不太完整。
```python
# Generate a static CFG
cfg = proj.analyses.CFGFast()

# generate a dynamic CFG
cfg = proj.analyses.CFGEmulated(keep_state=True)
```

- Using the CFG

CFG 的本质是 [NetworkX](https://networkx.org/) 有向图，所有正常的 NetworkX API 都可用：

- Function Manager
CFG 生成一个名为 Function Manager 的对象，可通过 `cfg.kb.functions` 访问。它将地址映射到 Function 对象，可以获得有关函数的属性。
```python
entry_func = cfg.kb.functions[p.entry]
```
  - `entry_func.block_addrs`: 是属于该函数起始的一组基本块的地址。
  - `entry_func.blocks`: 是属于该函数的一组基本块，可以使用 capstone 来反汇编。
  - `entry_func.string_references()`: 返回一个列表，包含所有在函数中任意位置引用的常量字符串。它们的格式为 (addr, string) 元组，其中 addr 是字符串所在的二进制数据部分中的地址，string 是包含该字符串值的 Python 字符串。
  - `entry_func.returning`: 是一个布尔值，用于表示一个函数是否可以返回。如果该值为 False，则表示该函数的所有执行路径都不会返回。
  - `entry_func.callable`: 是一个引用此函数的 angr Callable 对象。可以像使用 Python 函数一样调用它，并返回实际结果（可能是符号）。
  - `entry_func.transition_graph`: 是一个 NetworkX 有向图，描述函数本身内的控制流。
  - `entry_func.name`: 是函数的名称。
  - `entry_func.has_unresolved_calls` 和 `entry.has_unresolved_jumps` 与CFG中的不准确性有关。如果分析无法检测间接调用或跳转的可能目标是什么时，则该函数会将相应的 has_unresolved_* 值设置为 True。
  - `entry_func.get_call_sites()`: 返回一个列表，包含所有以调用其他函数为结尾的基本块的地址。
  - `entry_func.get_call_target(callsite_addr)`
  - `entry_func.get_call_return(callsite_addr)`