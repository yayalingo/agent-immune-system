# RESEARCH — Agent Immune System

> Stage 0 调研笔记。目标：为 PRD 提供事实依据。所有结论基于 2026-08-18 网络检索，后续需随事实更新。

## 1. 威胁底座：OWASP Top 10 for Agentic Applications（2025-12 发布）

由 100+ 安全研究者制定，使用 **ASI** 编码。与 LLM Top 10 并存、二者对 agentic 系统都适用。

| ASI | 风险 | 一句话 |
|---|---|---|
| ASI01 | Agent Goal Hijack | 对抗输入重定向 agent 目标（EchoLeak） |
| ASI02 | Tool Misuse & Exploitation | 合法工具被组合滥用（Amazon Q） |
| ASI03 | Identity & Privilege Abuse | agent 冒充人类 / 自提权 |
| ASI04 | Agentic Supply Chain | 恶意 MCP server、被投毒框架/子 agent（GitHub MCP exploit） |
| ASI05 | Unexpected Code Execution | 生成代码未沙箱执行（AutoGPT RCE） |
| ASI06 | Memory & Context Poisoning | 注入持久记忆/长上下文（Gemini Memory Attack） |
| ASI07 | Insecure Inter-Agent Comm | 多 agent 消息无认证/完整性校验 |
| ASI08 | Cascading Failures | 单点失败经重试/工具链放大 |
| ASI09 | Human-Agent Trust Exploitation | 利用人类对 agent 的信任 |
| ASI10 | Rogue Agents | 失控/自保型 agent（Replit meltdown） |

**对产品的含义**：Red-Team Kit 的攻击模式与 Coverage Dashboard 的维度，应直接映射到这 10 项 ASI。注意 agentic 风险"本质是时间性的"——多轮时序攻击（第 N 轮埋雷、第 M 轮爆发）是核心测试手法。

## 2. 竞品 / 基准格局（已确认存在）

### ClawMoat（最强直接竞品）
- 开源 agent 防火墙，MIT，零依赖 npm 包。三层防御：入站扫描 → YAML 策略引擎 → 出站扫描。
- 自带 **40/40 eval suite（100% 检测、0 FP）**。
- 官方 OWASP Agentic 覆盖声称：**8/10 ✅ + 2/10 🔜**（ASI05、ASI06 标记为待做）。
- 策略即 YAML，非通用策略引擎（不输出 Rego/Cedar）。

### sentinelseed（对齐/护栏系，Python）
- Python SDK，22+ 框架集成（LangChain、CrewAI、OpenAI Agents、PyRIT、Garak…）。
- 官方 OWASP Agentic 覆盖：**65%**（5 full + 3 partial），即约 6.5/10。
- 偏"对齐/合规"（EU AI Act、THSP gates），非纯攻防闭环。

### AGT — 微软 Agent Governance Toolkit（✅ 已确认，最强直接竞品）
- 微软开源、MIT，多语言 SDK（Python / TypeScript / .NET / Rust / Go）。
- **10/10 全覆盖** OWASP Agentic Top 10；13,000+ 测试、992 conformance tests、10 份正式 spec。
- 策略引擎支持 **YAML / OPA-Rego / Cedar** 三种；亚毫秒级（p50 0.012ms）、**fail-closed**（评估出错即拒绝）。
- 组件：Policy Engine、Zero-Trust Identity（AgentMesh，Ed25519 + 行为信任分 0–1000）、Execution Sandbox（Ring 0–3 + Kill Switch + Saga）、MCP Security Gateway、Agent SRE（熔断/SLO/混沌）、Merkle 审计链。
- 20+ 框架适配（LangChain、CrewAI、OpenAI Agents、Semantic Kernel、AutoGen…）。
- **关键缺口（我们的切口）**：AGT 是"运行时治理**执行**层"——你写/配策略，它确定性执行。但它**不做**"自动红队测试 → 把失败场景**编译**成可部署规则"的闭环。其 992 测试是 conformance/回归，不是攻击→规则合成的自动流水线。
- **定位关系**：AIS 与 AGT **互补而非纯竞争**——AIS 是"规则生产+测试+覆盖"层，可把生成的规则部署进 AGT（或独立 OPA/Cedar/Casbin）。引擎无关是我们的护城河。

## 3. 策略引擎对比（Rule Compiler 的下游目标）

Rule Compiler 需把"攻击特征"编译成可部署规则，兼容主流引擎。三者定位不同：

| 维度 | OPA / Rego | AWS Cedar | Casbin |
|---|---|---|---|
| 定位 | 通用策略引擎（CNCF 毕业） | 细粒度授权语言（CNCF sandbox 2025） | 多语言授权库（嵌入） |
| 语言 | Rego（声明式、图灵完备、学习曲线陡） | Cedar（JSON 风、受限、可形式化验证） | PERM 元模型 + CSV/Conf |
| 验证 | 无内置形式化验证 | **Z3 SMT 验证（~75ms 静态分析冲突）** | 无 |
| 性能 | 1–5ms，数据大时退化 | **比 Rego 快 42–60x** | 嵌入最快（无网络开销） |
| 部署 | sidecar/daemon/库/Wasm，bundle 原子热重载 | 库 / sidecar | 库内嵌（多语言） |
| 多引擎 | 原生 | AWS Verified Permissions | 跨语言 |
| 风险点 | Apple 收购 Styra（商业维护方），OSS 仍 CNCF | 生态较新、AWS 出身 | 无 UI/分发/审计工具，需自建 |

**对 Rule Compiler 的启示**：设计一层**策略中间表示（IR / Policy IR）**，再分后端 emit：
- `emit_reго.py` → Rego（最灵活，覆盖复杂时序/聚合）
- `emit_cedar.py` → Cedar（高保障、可静态验证冲突，适合"注入前先证明无害"）
- `emit_casbin.py` → Casbin Conf+CSV（轻量嵌入、快速落地）
这样"一次编译，多引擎部署"，是差异化卖点。

## 4. 关键开放问题（决定 PRD 走向）
1. **技术栈**：Python 优先 / TS 优先 / 混合？
2. **v1 范围**：仅核心闭环 / + Dashboard / + Drift / 四模块全做？
3. **交付形态**：CLI+库 / 常驻服务+Web / 两者？
4. **AGT 对标**：已确认 = 微软 Agent Governance Toolkit（10/10 覆盖、支持 Rego/Cedar）。AIS 定位为其"规则生产+测试+覆盖"互补层，引擎无关。

## 5. 一句话定位确认
> 开源红队-治理闭环平台：自动对 AI Agent 跑 OWASP Agentic Top 10 攻击测试，把失败的测试场景自动编译成可部署的治理策略规则（OPA Rego / Cedar / Casbin）。

四模块：Red-Team Kit（多轮时序攻击）· Rule Compiler（攻击特征→策略规则）· Coverage Dashboard（10 项 ASI 覆盖度）· Drift Monitor（行为漂移监控）。
