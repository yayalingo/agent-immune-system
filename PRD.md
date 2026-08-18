# PRD: Agent Immune System (AIS)

> 版本：v0.1（Stage 1 草案，待行内评审迭代）
> 上游依据：RESEARCH.md（威胁底座、竞品、策略引擎对比）
> 决策已锁定：混合架构（Python 核心 + TS 前端）· v1 = 仅核心闭环 · 交付 = CLI + 库 · AGT = 微软 Agent Governance Toolkit

## 一句话定位
开源的「红队 → 治理」闭环平台：自动对 AI Agent 跑 OWASP Agentic Top 10 攻击测试，把**失败的测试场景自动编译成可部署的治理策略规则**（OPA Rego / Cedar / Casbin），再回归验证、持续监控。

## 目标用户
- **Agent 开发者 / 平台团队**：已部署或准备部署 AI Agent，需要证明"我对 10 项 ASI 风险有覆盖"，并希望覆盖来自真实攻击而非手工拍脑袋。
- **安全工程师（非 Agent 专家）**：需要一套可复现、可审计的红队+规则流水线，而不是只买一个黑盒防火墙。
- **合规 / 治理角色**：需要 coverage 证据（"我们覆盖了 ASI01–10 中的哪些"）。

## 用户故事
- 作为 Agent 开发者，我想对刚上线的 Agent 跑一遍标准攻击套件，以便知道它在哪些 ASI 风险上裸奔。
- 作为安全工程师，我想把一次失败的攻击**一键**变成一条可部署的防御规则，以便修复不依赖我手动写 Rego。
- 作为安全工程师，我想在注入规则后**重新跑同一攻击**确认它被挡住，以便闭环有证据、不是空头承诺。
- 作为治理角色，我想看到"10 项 ASI 里我们实际覆盖了几项"的报告，以便向审计/管理层交代。
- （未来）作为 Agent 开发者，我想让系统在我 Agent 的**长期行为**偏离基线时告警，以便捕获随时间发酵的漂移风险。

## 核心功能清单（v1 范围）

### 模块 A：Red-Team Kit（v1 完整）
可复现的**多轮时序**攻击场景库，直接映射到 OWASP Agentic Top 10（ASI01–10）。
- [ ] 每个场景含：`scenario_id`、`asi_id`、多轮 `turns`（发给目标 Agent 的交互序列）、`expected_vulnerable_behavior`、`detection_predicate`。
- [ ] 攻击本质是时间性的：例如 ASI06 记忆投毒 = 第 3 轮埋雷（向记忆写入恶意内容）、第 7 轮爆发（触发外泄）。场景库默认以多轮编排。
- [ ] 目标适配接口 `TargetAgent.send(turn) -> observation`，首批提供：本地函数适配器 + OpenAI Agents / LangChain 适配器（≥1 个可跑）。
- [ ] CLI：`ais redteam --target <adapter> --scenario <id|all>`。
- [ ] 产出结构化 findings：`[{scenario_id, asi_id, outcome: vulnerable|safe, evidence, attack_signature}]`。
- [ ] 验收：内置 ≥3 个 ASI 场景可端到端跑通并产生 findings；其中至少 1 个在"裸"目标上复现 vulnerable。

### 模块 B：Rule Compiler（v1 完整，先单引擎）
把 failing finding 编译成可部署策略。
- [ ] **策略中间表示（Policy IR）**：从 v1 第一天起就是引擎无关的结构化描述（trigger / conditions / action），保证后续 Cedar/Casbin 后端只是"新 emitter"。
- [ ] v1 后端 `emit/rego.py`：IR → OPA Rego package（allow/deny + 攻击特征匹配）。
- [ ] CLI：`ais compile <findings.json> --engine opa -> bundle.aip`；输出可被人审阅、可进 Git。
- [ ] 注入：`ais deploy <bundle.aip>`（写入策略库 / bundle；v1 用本地文件或 OPA 本地 bundle，不做托管服务）。
- [ ] 验收：给定 1 个 vulnerable finding，一条命令产出合法 Rego；`opa test` 对该规则通过。

### 模块 C：回归验证（v1 完整，闭环收口）
- [ ] `ais redteam --target <adapter> --scenario <id> --with-policy <bundle.aip>`：在目标上重跑同一攻击，断言 outcome 由 `vulnerable` 翻转为 `safe`。
- [ ] 产出回归报告：场景 / 注入前 / 注入后 / 结论(pass|fail)。
- [ ] 验收：第 A 模块复现的 vulnerable 场景，经 B 编译+C 注入后回归为 safe（闭环绿）。

### 模块 D：Coverage 报告（v1 最小化，非看板）
- [ ] `ais coverage`：列出 ASI01–10，标注哪些已有 ≥1 条"已部署且回归通过"的防御规则。
- [ ] 输出纯文本/JSON（**不做 GUI**）。可视化 Dashboard 见 Phase 2。
- [ ] 验收：报告准确反映当前已部署规则覆盖的 ASI 项。

### 明确排除（v1 不做）
- ❌ Web GUI / Dashboard 可视化（Phase 2，用 TS/React）。
- ❌ Drift Monitor 长期行为监控（Phase 2+）。
- ❌ Cedar / Casbin 后端 emitter（Phase 2；IR 已就绪，只是加 emitter）。
- ❌ 运行时拦截代理（我们**部署规则进引擎**，不在中间件拦截——那是 AGT 的活）。
- ❌ 托管服务 / 多租户 / 账号体系。

## 交互与体验要求
- v1 全部走 **CLI + Python 库**（`import ais`）。命令风格参考 `ais <subcommand>`，输出机器可读（JSON）+ 人可读（表格）。
- 规则文件必须**人类可审阅、可进 Git、可 diff**——这是相对 AGT 黑盒配置的核心价值。
- 失败必须 fail-loud：编译/注入/回归任何一步出错要明确非零退出码与原因。

## 成功标准（v1 Definition of Done）
- [ ] 用户可对目标 Agent 跑 Red-Team Kit，得到 findings。
- [ ] 一条 failing finding 可一键编译成合法 OPA Rego 规则。
- [ ] 注入该规则并重跑，**同一攻击被挡住**（回归绿），闭环有证据。
- [ ] `ais coverage` 正确显示 N/10 ASI 覆盖。
- [ ] 核心流程在无任何 AI/LLM API 时也能完整跑通（确定性、可离线）。
- [ ] 测试命令全绿，无密钥入库。

## 差异化与竞争格局（核心卖点）
| 工具 | 覆盖 | 定位 | 与 AIS 关系 |
|---|---|---|---|
| **AGT**（微软） | 10/10 | 运行时治理**执行**层，策略引擎支持 Rego/Cedar，亚毫秒 fail-closed | **互补**：AIS 是其"规则生产+测试+覆盖"上游层，可把规则部署进 AGT |
| ClawMoat | 8/10 | 轻量 agent 防火墙，YAML 引擎，npm | 竞品偏执行；AIS 偏"自动生成规则" |
| sentinelseed | 65% | Python 对齐/合规护栏（EU AI Act） | 偏合规；AIS 偏攻防闭环 |

**AIS 的三条护城河**：① 自动"攻击→规则"合成闭环（AGT/ClawMoat 都不做）；② **引擎无关**（一次编译，部署进 AGT/OPA/Cedar/Casbin）；③ 规则**人类可审阅、可进 Git、可 diff** + coverage 证据。

## AI 能力补充（Stage 5 渐进增强，v1 不含）
v1 是确定性流水线，**不依赖任何 LLM**。Stage 5 可选叠加：
- **Agent Story（攻击变体生成）**：输入=一个已确认漏洞场景；思考=基于该 ASI 类型生成对抗变体（混淆/多语言/分片）；工具=`redteam.generate_variants`；输出=新场景加入库。
- **Agent Story（规则建议）**：输入=attack_signature；思考=建议 IR 条件与动作；工具=`compile.suggest`；输出=待人工审阅的 IR 草稿。
- **评估指标**：变体生成召回率（能否发现人工已知绕过）、规则建议采纳率（人工审阅后保留比例）、回归通过率。**所有 AI 输出必须人工审阅后才进规则库**（不自动部署）。

## 范围边界（非 v1，列入路线图）
- Phase 2：Coverage Dashboard（TS/React，对标 AGT 10/10、ClawMoat 8/10、sentinelseed 65%）+ Cedar/Casbin emitter。
- Phase 2+：Drift Monitor（长期行为基线 + 偏离告警）。
- Phase 5：LLM 辅助攻击变体生成与规则建议（见上）。
