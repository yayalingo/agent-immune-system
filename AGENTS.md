# AGENTS.md — Agent Immune System (AIS) 操作手册

> v1 实现期操作手册。随代码演进更新。规则反哺自审查错题本（见底部）。

## 1. 命令（可直接执行）
```bash
# 测试（零依赖，标准库 unittest）
python -m unittest discover -s tests -t . -v

# 闭环演示
python -m ais.cli redteam --target mock --scenario all --out findings.json
python -m ais.cli compile findings.json --engine opa --out bundle.aip
python -m ais.cli deploy bundle.aip --store ./store
python -m ais.cli redteam --target mock --scenario all --with-policy bundle.aip --evaluator ir --store ./store
python -m ais.cli coverage --store ./store
```
- `redteam` 裸跑发现漏洞时**故意返回 exit 2**（提示需处理）；回归模式全 safe 返回 0。
- stdout 仅输出 JSON（可被管道喂给 compile）；提示信息走 stderr。

## 2. 测试
- 框架：`unittest`（**零外部依赖**，无需 pytest/opa 即可跑核心）。
- 位置：`tests/`。6 文件：ir / emit_rego / runner / governor / coverage / e2e_loop。
- 覆盖率目标：core+compiler+redteam 关键路径 ≥80%。
- `test_emit_rego::test_ir_vs_opa_crosscheck`：仅当 `opa` 二进制存在时运行，校验 IR 评估器与真 Rego 决策一致（防漂移）；缺失则 `skipped`。

## 3. 项目结构
```
ais/
  cli.py                # 子命令入口
  core/{models,registry}.py
  adapters/local_fn.py  # 可控漏洞 mock 目标（v1 闭环用）
  redteam/{runner,scenarios/}.py
  compiler/{ir,emit/{rego,cedar,casbin}}.py
  eval/{ir_eval,opa_eval}.py   # 可插拔评估器
  governor.py           # 回归 harness（非运行时拦截）
  policy_store/local.py # 本地 store + manifest
  coverage/report.py
tests/
```

## 4. 代码风格
- 仅标准库（零运行时依赖）；类型注解 + dataclass。
- 相对导入层级：`ais` 直下模块用 `from .core...`；`ais.x` 子包模块用 `from ..core...`；`ais.x.y` 用 `from ...core...`。
- 枚举（MatchOp/Effect/TriggerEvent）用 `.value` 序列化；PolicyIR 提供 `to_dict/from_dict`。

## 5. Git 工作流
- 分支：`feature/<模块>`；提交：`feat: / fix: / docs:` 前缀。
- **最高频约束：严禁提交密钥**（v1 不含任何外部密钥，store 仅存本地策略）。

## 6. 边界（绝对禁止 / 已知限制）
- Governor 是**测试 harness**，不在中间件拦截（真实拦截由部署的引擎负责）。
- `matches`(正则) 在 Cedar 无原生支持（Phase 2 处理）；IR 是引擎无关契约。
- v1 不做：GUI / Drift Monitor / Cedar-Casbin 后端 / 运行时代理。
- 真实框架适配器（OpenAI Agents / LangChain）是 Phase 2 验证项，目前仅 `mock`。

## 错题本（审查发现 → 修复）
- 相对导入层级写错（beyond top-level）：统一按包深度计数，见 §4。
- evaluator 当对象调 `.evaluate` 但传入的是函数 → 改为按 `__call__` 协议调用。
- `redteam` 裸跑与 `--out` 同时输出会污染 stdout 管道 → 提示信息改走 stderr。
- 多规则 Rego 拼接时每条都带 `package`/`default` → 重复非法；改为 `emit()` 统一头 + `emit_rule()` 只出单条规则。
- `opa eval` 用 `-i /dev/stdin` 在 Windows 原生 Python 下不存在 → 改为写临时文件传路径（跨平台）。
- 回归只按 outcome==safe 标 regression_passed，会误把"本就 safe"当策略覆盖 → 必须校验 evidence 含 `[BLOCKED:`（策略实际拦住）。
- CLI 写 `--out`/编译产物不创建父目录 → 指定嵌套路径会 FileNotFoundError（文档示例用 cwd 路径规避；若需可加 mkdir）。
- 未知 scenario id 抛裸 KeyError → 在 cmd 层捕获，给出清晰报错并 exit 2。
- docs 与代码漂移：命令名（`redteam run`/`coverage report`）、产物名（`rule.rego`）、文件名（`rega.py`/`target.py`/`fixtures/`）要随实现同步修正。
