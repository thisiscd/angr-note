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