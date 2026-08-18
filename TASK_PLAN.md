# TASK_PLAN — Agent Immune System (AIS) v1

> 状态跟踪：PRD/SPEC 已确认，进入 Stage 4 实现。每个任务可独立实现与测试。
> 测试用 Python 内置 `unittest`（零依赖）；`opa` 为可选后端，缺失时相关测试跳过。

## 任务清单
- [x] T0 工具链探测 + SPEC §5.2 修订（可插拔评估器，零硬依赖）
- [x] T1 建项目骨架：TASK_PLAN.md、目录结构
- [x] T2 `core/models.py`：dataclasses + Scenario 注册表
- [x] T3 `adapters/local_fn.py`：VulnerableAgent mock 目标（可控漏洞）
- [x] T4 `redteam/runner.py` + `redteam/scenarios/`：3 个 ASI 场景（ASI01/02/06），多轮时序
- [x] T5 `compiler/ir.py`：signature → PolicyIR
- [x] T6 `compiler/emit/rego.py`：IR → OPA Rego（+ cedar/casbin 桩）
- [x] T7 `eval/ir_eval.py` + `governor.py`：可插拔评估器（ir 默认 / opa 可选）+ GovernedTarget 回归 harness
- [x] T8 `policy_store/local.py`：本地写入 + manifest
- [x] T9 `coverage/report.py`：ASI01–10 覆盖计算
- [x] T10 `cli.py`：argparse 子命令（redteam/compile/deploy/coverage）
- [x] T11 测试：6 个测试文件（13 用例，1 因 opa 缺失跳过）
- [x] T12 跑通全测试（OK, skipped=1）+ 端到端 CLI 闭环演示（3/10 覆盖）
- [x] T13 独立 Review Agent 代码审查并修复（🔴#1 重复 package 已修；🔴#2 opa `/dev/stdin`→临时文件；🟡#3 注释转义；🟡#4 compile/deploy 落 rego_test；🟡#5 回归仅当策略实际拦截才标通过；🟡#6 未知 scenario 清晰报错；🟢#8 SPEC/PRD 命令与路径引用修正）

## 验收（对应 PRD DoD）
- 裸跑 redteam → findings；compile → 合法 Rego（+ 测试）；deploy → 入库；--with-policy 回归为 safe；coverage 报告正确。
- 核心流程零 AI/LLM 依赖、无密钥入库。
- 全测试 17 用例通过（1 因 opa 缺失跳过）。

## 验收（对应 PRD DoD）
- 裸跑 redteam → findings；compile → 合法 Rego；deploy → 入库；--with-policy 回归为 safe；coverage 报告正确。
- 核心流程零 AI/LLM 依赖、无密钥入库。
