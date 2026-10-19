# ARTEX／AI Agent 偵測報告之技術質疑與修正建議

## 文件目的

本文件針對《Artex / AI Agent 攻擊偵測－分析人員技術細節》中，從三日 SIEM 紀錄推論「AI Agent／ARTEX 行為」的論證提出技術質疑與修正建議。

本次已知前提為：

- 原分析者確實讀取過完整 ARTEX 專案架構與相關原始碼。
- 三份 SIEM 紀錄已知是由 ARTEX 測試活動產生。
- 本文件不是否定原始碼分析，也不是否定事件來源為 ARTEX。
- 本文件主要檢視的是：**如果未來面對未知來源，僅靠 SIEM 可觀測資料，是否足以區分 AI Agent、傳統掃描器與具自動化能力的真人攻擊者。**

因此，以下質疑集中在「可觀測證據與歸因結論之間是否存在足夠因果證據」，而不是質疑 ARTEX 本身具有 LLM、Planner、Worker、Tool Call、Playwright、ScopeSentry 或並行執行能力。

---

## 一、總體結論

完整 ARTEX 原始碼可以證明：

1. ARTEX 具備 AI Agent 架構。
2. ARTEX 可呼叫 LLM。
3. ARTEX 可由一次模型回應產生多個 Tool Call。
4. ARTEX 可使用瀏覽器、自訂工具與掃描平台。
5. ARTEX 可並行處理多條任務。
6. ARTEX 可形成探索、執行、觀察與後續任務的工作循環。

但是，以上屬於**工具能力證據**。SIEM 中看到的時間間隔、TCP Session、User-Agent、URL、Payload 與 WAF／IPS 告警，屬於**網路行為證據**。

兩者要形成強歸因，仍需證明：

> 特定一段 SIEM 行為，確實由特定 ARTEX Planner／Worker／LLM／Tool Call 所產生，而不是由 ARTEX 所調用的固定掃描模板、瀏覽器本身、ScopeSentry 外掛、Retry、Rate Limit 或其他排程機制造成。

因此，較穩健的結論應分為三層：

- **已確認來源層**：本次測試已知由 ARTEX 產生。
- **行為辨識層**：SIEM 可辨識為多工具、多階段、具目標適應能力的自動化安全測試活動。
- **未知來源歸因層**：僅靠相似 SIEM Pattern，尚不足以確認未知活動一定來自 AI Agent 或 ARTEX。

---

## 二、完整原始碼分析後仍成立的質疑

### 2.1 可變停頓不等同 LLM 推理時間

原報告以大量不同停頓秒數及高變異係數，推論該停頓符合「可變思考時間」，並用來排除固定腳本。

完整原始碼確實可證明 ARTEX 需要等待 LLM 回應。然而，SIEM 所觀察到的停頓仍可能同時受到以下因素影響：

- Target Response Time
- TLS 連線建立
- Connection Pool與Keep-Alive
- HTTP／2多工
- Playwright頁面等待
- ScopeSentry模組切換
- Tool Timeout
- Retry與Exponential Backoff
- Rate Limiting
- OAST輪詢週期
- Worker排程與任務佇列
- Proxy與側錄流程
- 多條並行任務相互交錯
- 防火牆Session建立與回收機制

因此：

```text
高變異停頓 ≠ 已證明為LLM推理時間
```

較嚴謹的表述為：

> 事件呈現非固定節奏及批次與等待交替現象，與ARTEX的模型呼叫及Tool Call批次架構相容；但僅憑SIEM時間間隔，無法排除非同步掃描、模組等待、重試退避及目標端延遲。

若要將停頓直接歸因為 LLM，應進行下列對時：

```text
ARTEX LLM request start
→ ARTEX LLM response completed
→ Worker received ToolUses
→ Tool execution start
→ HTTP request observed by target
→ SIEM event time
```

只要多個週期都能穩定對上，才可將該延遲帶提升為 ARTEX／LLM 行為指紋。

---

### 2.2 TCP Session不能直接等同HTTP Request或Tool Call

原報告以 PAN-OS Start Event 的中位間隔、爆發群與並行 Session，對應 ARTEX 一次模型回應產生多個 Tool Call。

原始碼可證明 ARTEX支援並行與批次 Tool Call，但網路層仍存在以下非一對一關係：

```text
一個Tool Call可能產生多個HTTP Request
一個HTTP Request可能重用既有TCP Session
一個瀏覽器頁面可同時載入多個資源
一個TCP Session可承載多個HTTP Request
HTTP/2可於單一連線多工
一個Request可能被多套設備重複記錄
```

因此 PAN-OS Session可證明：

- 活動高度自動化
- 流量密集
- 存在並行網路活動
- 存在階段性Burst

但不能單獨證明：

- 一個Session就是一個Tool Call
- 一個Burst就是一次LLM回應
- 一段停頓就是模型推理

建議將相關敘述由「因果證明」改為「架構相容性證據」。

---

### 2.3 17至20秒停頓不能直接命名為「模型思考」

即使ARTEX確實呼叫LLM，群間17至20秒的停頓也不必然完全由模型延遲造成。相同週期可能來自：

- Browser等待頁面或Network Idle
- Scanner Batch完成等待
- OAST Callback輪詢
- Task Queue Polling
- Retry Timeout
- 模組排程週期
- Proxy處理延遲
- Target端應用延遲

因此不建議將規則命名為：

```text
AI Thinking Rhythm
LLM Reasoning Pause
Turn節奏
```

建議改為：

```text
Burst-and-Pause Automated Activity
階段性批次與等待活動
Suspected Agent-Like Burst Pattern
```

待實驗室基準證明該延遲與ARTEX LLM呼叫高度同步後，再建立ARTEX專屬子規則。

---

### 2.4 高變異係數只能排除部分簡易腳本

原報告以「固定sleep腳本應只有一至兩種停頓值，CV接近零」來排除腳本。這只能排除部分簡單實作，不能排除進階自動化工具。

非AI腳本與掃描平台可具備：

- Random Jitter
- 非同步工作池
- 多執行緒
- 不同模組不同Timeout
- 動態Rate Limit
- 指數退避
- 網路延遲繼承
- 目標回應驅動的等待
- Crawler接Scanner的工作流

因此較精確的結論為：

> 高CV與大量停頓值不符合單一固定sleep的簡易腳本，但仍可能由多模組、非同步、具重試和Jitter的傳統自動化平台產生。

---

### 2.5 應用專屬Endpoint不等同AI理解

原報告觀察到：

- 先抓JavaScript
- 後續存取應用專屬API
- 再針對真實Endpoint進行測試

這和ARTEX的`api-recon`能力高度吻合。然而，非LLM工具也可做到：

- HTML Crawler
- JavaScript Endpoint Extractor
- OpenAPI／Swagger解析
- Form與Parameter擷取
- Browser Network Capture
- 將Crawler結果自動送入Vulnerability Scanner
- 依技術指紋啟用模板

因此現有證據能證明：

```text
存在Endpoint Discovery與後續掃描的整合工作流
```

但尚不能單靠此點證明：

```text
LLM理解了Endpoint語意並自主決定下一步
```

更強的Agent證據應包含：

- 後續Request使用前一Response才出現的隨機Endpoint
- 後續Request使用前一Response才出現的自訂參數名稱
- 根據應用自訂錯誤訊息修正Method或Body格式
- 根據非固定業務語意選擇相符測試
- 使用一次性Token完成多階段鏈

---

### 2.6 路徑變形不等同「被擋後即時改策略」

下列變體確實證明系統化測試：

```text
../
./
//
;jsessionid=
;x=1
完整URL與相對URL切換
```

但要證明「Agent被擋後根據結果改策略」，至少需要：

1. Request A先出現並被阻擋。
2. Request B在A之後出現。
3. A、B指向相同基礎Endpoint。
4. B的變形可合理對應A的阻擋原因。
5. 不同執行中變形順序會依結果改變，而非固定模板順序。

若每次都固定執行：

```text
../ → ./ → // → ;x=1
```

則更像掃描模板或Payload字典，而不是模型即時推理。

因此P4可以作為「自動化繞過測試」證據，但不宜單獨作為AI Agent證據。

---

### 2.7 跨框架Payload較直接證明多模板掃描

短時間出現Log4j、Struts、WebDAV、SQLi及其他Payload，最直接的解釋是：

```text
多漏洞模板或多Plugin批次執行
```

此行為與ARTEX調用ScopeSentry或其他掃描工具相容，但並非AI專屬。傳統掃描平台本來就能依序或並行執行多種漏洞模板。

如果已辨識目標為特定技術棧，但仍對大量無關框架投放Payload，這甚至可能表示：

- 技術辨識不精確
- 廣泛Template Sweep
- Scanner廣度優先
- ScopeSentry插件批次執行

因此P5較適合命名為：

```text
Multi-Technique Automated Vulnerability Scanning
多技術類型自動弱點測試
```

不應高權重地視為AI Agent專屬特徵。

---

### 2.8 `users-online-counter`可能是應用程式輪詢

`users-online-counter`的大量重複請求確實具有狀態查詢特徵，但也可能來自：

- SPA本身的定時輪詢
- 頁面元件自動更新
- 每次Reload自動呼叫
- 多次建立Browser Context
- Route Traversal反覆觸發Bootstrap
- 應用Heartbeat

因此不能直接把該Endpoint對應為Agent Worker的Observe步驟。

較安全的結論為：

> ARTEX的瀏覽器探索或頁面遍歷觸發了大量狀態Endpoint請求；目前無法僅靠SIEM確認這些請求是Worker主動觀察，還是目標前端程式自動輪詢。

要確認需比對：

- Playwright Trace
- Browser Network Log
- ARTEX Traffic ID
- Worker Loop時間
- 頁面端JavaScript Timer

---

### 2.9 多線並行是自動化證據，不是AI專屬證據

原始碼中的`maxParallel`可證明ARTEX具備多線並行能力。SIEM中的同時Session也與此能力相容。

然而，以下工具同樣能產生多線並行：

- Nuclei
- Burp Active Scan
- Dirsearch／ffuf
- 多Worker Crawler
- 多執行緒自製掃描器

因此P7應支援：

```text
高度自動化／平行化
```

但不能單獨支援：

```text
一定是AI Agent
```

只有當每條並行線都能對應到獨立Task Context、獨立Observation及後續差異化決策時，才更接近Agent證據。

---

### 2.10 多User-Agent證明多工具或偽裝，不證明AI

同一來源出現Browser、curl、probe及畸形User-Agent，可證明：

- 多工具共用出口
- UA Rotation
- 自動化偽裝
- Browser與CLI協作

但無法區分：

- ARTEX Agent
- 傳統整合掃描平台
- 真人使用多種工具
- 多個模組共用NAT

另外，針對「不存在的Chrome版本」等判斷，應以事件日期當日的實際版本資料驗證，避免僅以直覺認定畸形。

規則名稱建議使用：

```text
Multi-Tool or User-Agent Rotation Activity
```

不要直接命名為：

```text
AI Agent User-Agent Fingerprint
```

---

## 三、「七項同時成立」仍不能排除非AI流水線

原報告主張七項Pattern同時成立時，幾乎只剩AI Agent一種解釋。這項說法仍過強。

以下非AI流水線也可能同時符合多項Pattern：

```text
Browser Crawler
→ JavaScript Endpoint Extractor
→ Directory Scanner
→ Vulnerability Template Engine
→ OAST Verification
→ Parallel Workers
→ Retry／Backoff／Jitter
```

該流水線可以產生：

- 多User-Agent
- JavaScript探索
- 應用Endpoint提取
- 路徑變形
- 多漏洞Payload
- 狀態Endpoint重複
- 多線並發
- Burst與Pause

因此，多項Pattern同時成立可提高下列判斷信心：

> 多工具、多階段、具狀態追蹤或目標適應能力的整合式自動化平台。

但要提升到「AI Agent」，仍應加入至少一項Response-driven因果證據。

---

## 四、對ArcSight規則的修正建議

### 4.1 R1不宜命名為Turn節奏

原設計偵測：

```text
微爆發 → 10至25秒停頓 → 再微爆發
```

此模式可以偵測階段性自動化活動，但ArcSight一般Aggregation不擅長直接表達多輪序列與可變停頓。

建議：

- 規則名稱改為`Burst-and-Pause Automated Activity`。
- 使用Active List或外部預計算欄位記錄Burst時間。
- 將R1視為自動化活動分數，不直接標記為LLM推理。
- ARTEX專屬版本需用實驗室基準中的LLM／Tool Call時間校準。

### 4.2 R2改為多工具／UA輪替

保留Distinct UA與CLI／Browser共現條件，但命名為：

```text
Multi-Tool Automated Web Activity
```

此規則只給低至中權重，並排除：

- NAT出口
- Proxy
- CDN
- 合法弱掃平台
- 已核准Red Team來源

### 4.3 R3移除404比例，除非補齊Full Access Log

原報告已承認WAF不是完整Access Log，因此：

```text
404比例低
```

目前不可計算，也不應出現在實際規則門檻。

R3可改為：

```text
先出現前端資源或JS活動
→ 後續出現多個應用專屬Endpoint
→ 再對部分Endpoint集中測試
```

但規則名稱應為：

```text
Frontend Discovery Followed by Application-Specific Probing
```

而不是直接稱為AI語意理解。

### 4.4 R4保留，但定位為Endpoint Mutation

R4可以落地，建議偵測：

```text
../
/./
//
;jsessionid
;x=
編碼變形
```

規則名稱：

```text
Systematic Endpoint Mutation Activity
```

若要提升Agent分數，需再加入「前一請求被擋後才出現新變形」的序列條件。

### 4.5 R5降低AI權重

跨框架Payload更像Vulnerability Template Sweep。建議：

- 保留為自動掃描證據。
- 權重維持低。
- 不與R1一同直接判定AI High。
- 規則名稱改用`Multi-Technique Vulnerability Scan`。

### 4.6 R6a更名為高頻Endpoint輪詢

```text
High-Frequency Application Endpoint Polling
```

不要直接稱為Agent Observe Loop。若能證明輪詢與Worker Cycle同步，再新增ARTEX專屬加分。

### 4.7 R6b證明並行，但不證明每條線在思考

同時2至5條Session可作為Parallel Automation證據。要聲稱每條線具有獨立Agent節奏，需有：

- Conversation ID
- Worker ID
- Task ID
- Tool Run ID
- Traffic ID

與SIEM Session的對應。

### 4.8 R0最終事件名稱應保守

建議分級：

```text
Automated Web Reconnaissance
Suspected Adaptive Automated Web Activity
High-Confidence Response-Driven Agent-Like Activity
Known ARTEX Activity（需內部Task／Traffic證據）
```

不建議僅靠R1至R6累計後直接命名：

```text
AI Agent Detected
```

---

## 五、建議重新定義證據等級

### Level 1：已確認事實

現有資料可確認：

- 活動高度自動化。
- 存在多工具或多User-Agent。
- 存在大量並行或高頻連線。
- 存在前端資源與應用專屬Endpoint活動。
- 存在敏感路徑、Endpoint變形及多漏洞Payload。
- 10/14與10/15為相同標的、不同來源。
- 10/16為新標的並呈現不同技術棧與大量POST活動。
- 本次已知測試來源為ARTEX。

### Level 2：架構相容性證據

下列行為與ARTEX原始碼架構相容：

- Burst-and-Pause與模型／Tool Batch工作流相容。
- 多Session與Parallel Worker相容。
- Browser及CLI共現與Playwright／Custom Tool能力相容。
- JS／API探索與`api-recon`相容。
- 多漏洞Payload與ScopeSentry／外部Plugin相容。

此層應使用「相容」、「吻合」、「可由該架構解釋」，而不是「已證明由該程式碼路徑直接造成」。

### Level 3：尚需因果證明

以下結論需ARTEX內部Telemetry與SIEM對時：

- 某個停頓就是某次LLM推理。
- 某個Burst就是某次ToolUses批次。
- 某個Session對應某個Tool Call。
- 某個Endpoint由前一Response新發現。
- 某個Payload由模型依前一結果動態生成。
- 某次路徑變形是因前一請求被WAF阻擋後產生。
- 某組平行Session對應五個獨立Worker。

---

## 六、要將信心提升為高的驗證方式

### 6.1 建立跨層Correlation ID

建議ARTEX每個執行階段產生：

```text
Run ID
Conversation ID
Task ID
Worker ID
Tool Call ID
Traffic ID
Parent Task ID
```

並在不影響測試效果的實驗環境中，以Header或Proxy Metadata帶入：

```text
X-ARTEX-Run-ID
X-ARTEX-Task-ID
X-ARTEX-Tool-ID
```

隨後比對：

```text
ARTEX內部事件
→ Proxy Traffic
→ Target Access Log
→ WAF／IPS
→ ArcSight
```

### 6.2 受控Response-driven測試

建立不可能存在於公開字典的動態資料：

```text
隨機Endpoint
隨機Parameter Name
一次性Token
自訂錯誤訊息
動態Method要求
動態Content-Type要求
```

例如：

```text
Response 1：Parameter lunarFileToken is required
Response 2：POST with application/json is required
Response 3：Next endpoint is /stage/{random-id}
```

若ARTEX能依序修正：

```text
加入lunarFileToken
→ 改POST
→ 改JSON
→ 存取隨機Endpoint
```

則可直接證明後續行為由前一Response驅動，而不是固定掃描字典。

### 6.3 建立比較基準

同一靶機分別由以下工具執行：

- ARTEX
- Nuclei
- Burp Active Scan
- 傳統Crawler＋Scanner Pipeline
- 真人操作

比較：

- Inter-arrival distribution
- Burst shape
- Endpoint discovery chain
- Tool switching
- Mutation order
- Response-driven correction
- Parallel branch divergence

只有在ARTEX呈現穩定、可重現且與對照組顯著不同的特徵後，才能建立較可靠的專屬指紋。

---

## 七、建議修正版結論文字

> 三日SIEM資料顯示，本次活動具有高頻、平行、多工具、多階段、應用專屬Endpoint探索及後續漏洞測試等特徵。由於本次測試來源已知為ARTEX，這些事件可作為ARTEX在目前環境中的行為基準；相關行為亦與ARTEX原始碼中的LLM呼叫、並行Worker、批次Tool Call、Playwright、自訂工具及ScopeSentry整合能力相容。
>
> 然而，未知來源事件若僅呈現相同Pattern，仍不能直接確認為AI Agent或ARTEX。可變停頓、多User-Agent、路徑變形、跨框架Payload、狀態Endpoint重複及多Session並行，也可由進階掃描器、Crawler與Scanner流水線、Retry／Backoff或多Worker排程產生。現有SIEM資料尚缺乏「前一Response直接驅動下一個Request」及ARTEX內部Task／Tool Call與網路事件的一對一對時證據。
>
> 因此，現階段規則宜識別為「疑似Agent型適應式自動化活動」，並將已知ARTEX執行紀錄用於基準建模。若能補充ARTEX Run／Task／Worker／Tool Call／Traffic ID、完整HTTP Request／Response及Proxy或Web Access Log，即可將架構相容性證據提升為因果歸因，並建立較高可信度的ARTEX專屬偵測規則。

---

## 八、最終意見

原報告的主要價值仍然成立：

- 已將ARTEX架構與SIEM可觀測行為建立初步對照。
- 已整理一組可實驗驗證的候選Pattern。
- 已提出加權式ArcSight規則，而非依賴單一IOC。
- 已主動揭露WAF／IPS取樣偏差與資料限制。

需要修正的不是「ARTEX是不是AI Agent」，因為完整原始碼已能回答這件事；真正需要修正的是：

> **相同SIEM Pattern是否足以讓防守方在未知來源情境下，排除傳統掃描器並確認對方是AI Agent。**

目前答案仍是：

```text
可以辨識為高度自動化、具目標適應能力、與ARTEX架構吻合的Agent-Like活動；
但若缺少Response-driven因果證據與ARTEX內部Telemetry，尚不足以完成未知來源的AI Agent強歸因。
```
