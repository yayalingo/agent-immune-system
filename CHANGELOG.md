# CHANGELOG — Agent Immune System (AIS) v1

> 所有变更先改文档（PRD/SPEC/TASK_PLAN）后改代码；此处只记"发生了什么 + 影响范围"。

## [v1.0.0] 2026-08-18 — Stage 4 完成 + 独立审查修复
**阶段**：Stage 0 研究 → 1 PRD → 3 SPEC → 4 实现 + 独立代码审查，全部收口。

**新增能力（核心闭环）**
- Red-Team Kit：3 个 ASI 场景（ASI01 目标劫持 / ASI02 工具滥用 / ASI06 记忆投毒），多轮时序攻击，mock 目标 `VulnerableAgent`。
- Rule Compiler：failing finding → 引擎无关 `PolicyIR` → OPA Rego（单一 `package agent.policies`，可进 Git、可被 `opa test` 验证）。
- 回归 harness（Governor）：`--with-policy` 重跑，断言 vulnerable→safe，证明生成的规则会拦攻击。
- Coverage：ASI01–10 覆盖报告（文本/JSON），v1 实测 3/10 (30%)。
- 可插拔评估器：`ir`（零依赖默认）/ `opa`（可选，缺二进制时跳过交叉校验）。

**审查修复（独立 Review Agent 发现）**
- 🔴#1 多规则 Rego 重复 `package` → 重写 `emit/rego.py`（`emit` 统一头 + `emit_rule` 单条）。
- 🔴#2 `opa eval` Windows 下 `/dev/stdin` 不存在 → 改写临时文件传路径。
- 🟡#3 Rego 注释含换行/注入 → `_safe_comment` 折叠空白。
- 🟡#4 `compile`/`deploy` 现在一并落 `_test.rego`，支持 `opa test`。
- 🟡#5 回归仅当 evidence 含 `[BLOCKED:`（策略实际拦住）才标 `regression_passed`，避免误标覆盖。
- 🟡#6 未知 scenario id → 清晰报错 + exit 2，不再裸 traceback。
- 🟢#8 同步 SPEC/PRD：命令名（`redteam`/`coverage` 无 `run`/`report`）、产物名（`bundle.aip`）、文件名（`rego.py`/`models.governor`/`adapters/local_fn.py`）。

**测试**：17 用例通过（1 因 opa 缺失跳过）；新增 `_is_policy_blocked` 守卫与未知 scenario 测试。

**已知限制（v1 不做，见 PRD 排除项）**：无 GUI/看板、无 Drift Monitor、无 Cedar/Casbin 后端、无运行时拦截代理、无多租户、仅 mock 适配器。

**下一步（Phase 2，待确认）**：Coverage Dashboard（TS/React）、Cedar/Casbin emitter、Drift Monitor、真实框架适配器（OpenAI Agents / LangChain）。
