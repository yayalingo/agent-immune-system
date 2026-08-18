# Agent Immune System (AIS)

> 开源的「红队 → 治理」闭环：自动对 AI Agent 跑 OWASP Agentic Top 10 攻击，把失败场景编译成**引擎无关**的治理策略（OPA Rego / Cedar / Casbin），再做回归验证与覆盖度监控。

AIS 不是运行时拦截代理，而是**规则生产 + 测试 + 覆盖**的上游层：它证明"哪条攻击该被哪条策略拦住"，生成的策略可交给 OPA / AWS Cedar / Casbin 或微软 [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit) 等引擎执行。

## 为什么需要它

- AI Agent 会**多轮、带时间性**地出问题（例如 ASI06 记忆投毒：第 3 轮埋雷，第 7 轮爆发外泄），传统单轮测试抓不到。
- OWASP 2025-12 发布的 **Agentic Applications Top 10 (ASI01–ASI10)** 尚无开箱即用的红队→策略闭环工具。
- 现有方案定位不同：AGT 偏**运行时执行**（10/10 覆盖），ClawMoat 偏防火墙（8/10），sentinelseed 偏 EU AI Act 合规（65%）。AIS 与它们**互补**：自动产出可审计、可进 Git、可跨引擎的策略。

## 核心闭环（v1 已实现）

```
红队扫描 ──findings──▶ 规则编译 ──PolicyIR──▶ 策略包(.aip + .rego)
   │                        │                        │
   └──────── 回归验证(Governor) ◀───────────────────┘
                                    │
                              覆盖度报告 (ASI01–10)
```

1. `ais redteam --target mock --scenario all` → 跑攻击，产出 `Finding[]`（含攻击特征）。
2. `ais compile findings.json --engine opa` → 编译成 `bundle.aip` + `bundle.rego` + `bundle.rego_test`。
3. `ais deploy bundle.aip` → 写入本地策略库。
4. `ais redteam --target mock --scenario all --with-policy bundle.aip` → 用策略重跑，断言 `vulnerable → safe`。
5. `ais coverage` → ASI01–10 覆盖度（v1 实测 **3/10**，后续场景补齐）。

## 快速开始

```bash
# 零依赖运行（Python 3.10+，无需安装）
python -m ais.cli redteam --target mock --scenario all --out findings.json
python -m ais.cli compile findings.json --engine opa --out bundle.aip
python -m ais.cli deploy bundle.aip
python -m ais.cli redteam --target mock --scenario all --with-policy bundle.aip --evaluator ir
python -m ais.cli coverage
```

- **零硬依赖**：核心用 Python 标准库。
- **可选后端**：`opa` 二进制存在时，`--evaluator opa` 用真实 Rego 引擎交叉校验（缺省时自动跳过并 fall back 到内置 `ir` 评估器）。

## 架构

```
ais/
  core/         models(PolicyIR 等) · registry(场景注册) · governor(回归 harness)
  redteam/      runner + scenarios/(ASI01/02/06 等多轮时序攻击)
  compiler/     ir(signature→IR) · emit/(rego 已实现；cedar/casbin 见 Phase 2)
  eval/         ir_eval(默认零依赖) · opa_eval(可选)
  policy_store/ 本地落盘 + manifest
  coverage/     ASI01–10 覆盖计算
  adapters/     local_fn(故意漏洞 mock) · 真实框架适配器见 Phase 2
cli.py          子命令：redteam / compile / deploy / coverage
```

## 文档（活文档）

- `RESEARCH.md` — OWASP ASI 列表、竞品与策略引擎对比。
- `PRD.md` — 产品需求与验收标准。
- `SPEC.md` — 架构、Policy IR 契约、引擎适配。
- `AGENTS.md` — 操作手册与审查错题本。
- `CHANGELOG.md` — 变更记录。

## 路线图（Phase 2）

- [ ] **Coverage Dashboard**（TS/React 可视化看板）
- [ ] **Cedar / Casbin emitter**（引擎无关 IR 的另两条后端；Cedar 原生无 regex，`matches` 需转译）
- [ ] **Drift Monitor**（Agent 行为漂移监测）
- [ ] **真实框架适配器**（OpenAI Agents / LangChain，替换 mock）

## License

MIT（待补充 LICENSE 文件）。
