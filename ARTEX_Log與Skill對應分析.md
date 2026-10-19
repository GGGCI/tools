# ARTEX Log 與 Skill 對應分析

## 文件目的

本文件將2026年10月14日、10月15日及10月16日三日SIEM Log中可觀察到的行為，對應至`ARTEX_SKILLS_MERGED.md`內的`api-recon`、`playwright-cli`及`scopesentry`原始條文。

本文件目的不是僅因某項行為出現，就直接認定未知來源為ARTEX或AI Agent，而是說明：

- 哪些Log行為與ARTEX Skill定義高度吻合；
- 哪些行為只能證明自動化或掃描活動；
- 哪些具體攻擊Payload不是`api-recon`直接產生；
- SIEM目前能證明及尚不能證明的範圍。

> **行號基準**：本文行號皆依目前提供的`ARTEX_SKILLS_MERGED.md`版本。若檔案內容後續修改，行號可能位移。

---

# 一、三套Skill的整體分工

## Skill原始條文

| 行號 | Skill條文重點 |
|---:|---|
| 24 | `api-recon`用於枚舉網站後端API、前端路由及參數。 |
| 25 | `playwright-cli`用於瀏覽器自動化、點擊、填表、測試、截圖及Mock Network。 |
| 26 | `scopesentry`用於管理掃描平台、專案、任務、模板、資產及節點。 |
| 28 | 三者可配合：ScopeSentry收資產 → api-recon深挖接口 → playwright-cli復現／驗證頁面行為。 |

## SIEM整體觀察

三日Log呈現以下高階流程：

```text
接觸標的及資產
→ 前端HTML／JavaScript探索
→ 應用專屬API及路由出現
→ Browser頁面與表單操作
→ 敏感路徑及平台探測
→ 特定Endpoint集中測試
→ 多種漏洞Payload觸發WAF／IPS告警
```

## 對應判斷

三日事件與第24至28行描述的多Skill協作模式高度吻合：

```text
ScopeSentry負責資產與掃描任務
api-recon負責API、路由及參數探索
playwright-cli負責瀏覽器及頁面功能操作
ScopeSentry／Plugin負責後續漏洞驗證
```

但這個吻合只能證明ARTEX架構可合理解釋Log行為，不代表SIEM已將每筆事件一對一關聯至特定Skill或Tool Call。

---

# 二、前端HTML、JavaScript與Bundle探索

## SIEM看到的行為

10月14日可見：

```text
/dist/index.html
/dist/runtime.*
/dist/main.*
/dist/vendor.*
/dist/polyfills.*
/dist/chunks/*
/APP_A/js/*
```

10月16日新標的也出現首頁、前端資源及實際功能頁面載入。

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 75–80 | 靜態層從JS Bundle取得Endpoint路徑及路由；運行時層取得Method、Body、Response及動態URL。 |
| 84 | `runtime_harvest.js`用於API清單、Method、參數、Response及WS／SSE。 |
| 85 | Coverage模式使用Browser及`preload.js`點擊Tab、彈窗及表格。 |
| 86 | Both模式先執行Depth，再執行Coverage。 |
| 94–99 | Recon完成條件包含靜態輸出、運行時分析、參數矩陣、權限樹及資產寫入。 |
| 135–145 | 執行路線包含分類、靜態Harvest、參數逆向、運行時、權限樹及合併報告。 |
| 151–158 | 拉取入口HTML並區分SPA與MPA；MPA可執行Spider。 |
| 162–177 | Phase 1靜態Harvest，用於處理前端JS、Route及Endpoint。 |

## 吻合判斷

**吻合程度：高。**

前端入口、Runtime、Main、Vendor及Lazy Chunk的載入，與`api-recon`靜態Harvest及Browser初始載入流程一致。

## 判斷限制

正常Browser、傳統Crawler及JavaScript Endpoint Extractor也會取得相同資源，因此這項行為：

- 可作為前端探索證據；
- 可作為ARTEX Skill吻合證據；
- 不能單獨作為AI Agent或ARTEX專屬指紋。

---

# 三、應用專屬API、路由及功能探索

## SIEM看到的行為

### APP_A

```text
/APP_A/api/core/system/users-online-counter
/APP_A/api/core/system/load-chat-bot-info
/APP_A/api/core/system/setting
/APP_A/api/core/system/site-project
/APP_A/api/sitemap/project-info/side_menu
/APP_A/api/file/whitelist
/APP_A/create-validation-token.do
/APP_A/sso-redirect.do
/APP_A/servlet/openfile
```

### APP_B及APP_C

```text
/APP_B/home/index
/APP_B/common/sendlogindata
/APP_B/common/getpictureverify
/APP_B/common/checkpictureverify
/APP_B/common/_rsakey2048
/APP_B/common/sendcmsqry0001
/APP_B/home/uploaddocument
/APP_C/mbanktxn.action
```

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 35–37 | `api-recon`用於完整發現後端API的Path、Method、Parameter、Response，以及前端Route與UI觸發點。 |
| 53 | Stub登入、權限、選單等Bootstrap API。 |
| 54 | 對業務查詢API提供結構正確的Mock Body。 |
| 55 | 使SPA渲染並觸發更多XHR、Fetch及WebSocket。 |
| 58 | 只記錄Outbound Request，重點是前端還會發出哪些API。 |
| 79–80 | 靜態層取得Endpoint及Route；運行時層取得Method、Body、Response及動態URL。 |
| 84–85 | Depth與Coverage模式分別進行Runtime Harvest及UI功能覆蓋。 |
| 234–269 | Phase 3執行運行時探索及參數矩陣。 |
| 270–290 | Phase 4還原權限樹後再次進行Runtime探索。 |

## 吻合判斷

**吻合程度：很高。**

這些Endpoint不是單純的`/admin`、`/.git`等通用字典路徑，而是標的應用專屬的系統設定、選單、驗證、檔案、登入、Session及查詢功能。

這表示SIEM能觀察到：

```text
前端或Browser探索
→ 實際應用Endpoint出現
→ 部分Endpoint持續被觸發或測試
```

## 判斷限制

傳統Crawler、Browser Network Capture及JavaScript Extractor也能做到，因此此項是：

- ARTEX `api-recon`流程的強吻合證據；
- 應用導向探索的證據；
- 不是LLM自主推理的直接證據。

---

# 四、Method、Body及Parameter探索

## SIEM看到的行為

三日Log中可見：

- GET與POST比例隨標的改變；
- Parameter Type Violation；
- `fileName`、`id`、`go`、`userData`及`jData`等參數；
- APP_B具有大量登入、驗證碼、Session、查詢及上傳POST；
- Path Parameter及`jsessionid`變化；
- 部分Endpoint出現Method與路徑形式變化。

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 37 | 收集Path、Method、Parameter及Response。 |
| 79–80 | 靜態層取得欄位候選；運行時層取得Method、Body及Response。 |
| 88 | 參數分析使用錨點擴窗、UI綁定鏈、多樣本Diff及錯誤反推。 |
| 97 | 完成參數觸發矩陣、`param_samples.json`及`params_merged.json`。 |
| 140 | Phase 1b參數逆向。 |
| 178–218 | Phase 1b執行參數逆向。 |
| 234–269 | Phase 3執行Runtime及參數矩陣。 |

## 吻合判斷

**吻合程度：高。**

10月16日新標的大量POST及實際功能Endpoint，尤其符合`api-recon`及Browser Runtime對Method、Body及Parameter的收集能力。

## 判斷限制

Parameter探索不能直接等同SQL Injection或漏洞利用。`api-recon`只負責偵察及收集，不應把後續SQLi告警直接歸因至`api-recon`。

---

# 五、Browser及Playwright頁面操作

## SIEM看到的行為

- Chrome User-Agent；
- HTML、JavaScript及前端資源載入；
- 登入、驗證碼、RSA Key、Session、忘記密碼等功能；
- 大量POST表單及查詢功能；
- Browser與curl等CLI工具交替出現。

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 25 | `playwright-cli`用於瀏覽器自動化、點擊、填表及Network Mock。 |
| 343以後 | `playwright-cli`瀏覽器自動化章節。 |
| 359–405 | Browser Commands，包含開啟、導航、點擊、填寫及Network等操作。 |
| 406–442 | Cookie、LocalStorage及SessionStorage操作。 |
| 483–519 | Page Snapshot及Element Targeting。 |
| 547–590 | 表單提交、多Tab、DevTools、Tracing及UI Review範例。 |

## 吻合判斷

**吻合程度：高。**

APP_B的登入、驗證碼、RSA Key、Session、忘記密碼及文件上傳等Endpoint，與Playwright操作頁面、表單及前端互動的能力相容。

## 判斷限制

SIEM只能觀察Browser產生的Request及User-Agent，不能單靠Log證明每一筆Request一定由Playwright產生。要確認需補：

```text
Playwright Trace
Browser Network Log
ARTEX Traffic ID
Tool Call ID
```

---

# 六、通用敏感路徑及平台探測

## SIEM看到的行為

```text
/admin
/administrator
/.git/head
/.git/config
/web.config
/trace.axd
/WEB-INF/web.xml
/actuator
/phpinfo.php
/manager/html
/swagger-ui.html
/nginx_status
```

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 26 | ScopeSentry管理掃描平台、任務、模板、資產及節點。 |
| 619–642 | ScopeSentry工具包含Task、Plugin、Scan Template及Create Scan Task。 |
| 657 | 建立掃描任務，選擇Node及Template。 |
| 680–690 | 兩階段流程：先蒐集資產，再送往端口、資產及漏洞模組。 |
| 693 | 建立掃描模板，選擇Module、Plugin Hash及Parameter。 |
| 701 | 資產類型包含UrlScan、SensitiveResult、DirScanResult、Crawler及Vulnerability。 |
| 728 | DirScanResult保留URL、Status Code、Redirect及Length。 |
| 779 | 模組包含URLScan、WebCrawler、URLSecurity、DirScan、VulnerabilityScan及PassiveScan。 |

## 吻合判斷

**吻合程度：高。**

這些通用敏感路徑與ScopeSentry的URLScan、WebCrawler、URLSecurity及DirScan能力相容。

## 判斷限制

此類路徑也是一般弱掃工具常見行為，只能證明自動化掃描，無法單獨證明ARTEX或AI Agent。

---

# 七、特定File Handler集中測試及路徑變形

## SIEM看到的行為

10月14日至10月15日對APP_A File Handler出現：

```text
正常Endpoint
../
./
//
;jsessionid=
;x=
完整URL
相對URL
```

並觸發：

```text
Directory Traversal
WEB-INF存取
敏感檔案測試
WAF Rule命中
```

## 對應Skill原始條文

### Endpoint發現部分

| 行號 | 原始條文重點 |
|---:|---|
| 35–37 | `api-recon`發現API、Route、Method及Parameter。 |
| 75–88 | 靜態及Runtime探索Endpoint與Parameter。 |
| 234–290 | Runtime及權限樹探索。 |

### 後續漏洞掃描部分

| 行號 | 原始條文重點 |
|---:|---|
| 657 | 建立ScopeSentry掃描任務。 |
| 693 | 以Plugin及Parameter建立掃描模板。 |
| 729 | Vulnerability結果包含URL、漏洞名稱、Matched、Request、Response及Level。 |
| 779 | 使用DirScan及VulnerabilityScan等掃描模組。 |

## 吻合判斷

最合理的Skill鏈為：

```text
api-recon／Browser發現File Handler
→ Endpoint進入資產或任務
→ ScopeSentry／Plugin執行路徑及漏洞測試
→ WAF／IPS產生告警
```

## 判斷限制

SIEM目前不能證明：

```text
第一次被WAF阻擋
→ LLM讀取結果
→ 即時產生下一種Path Mutation
```

路徑變形可能是固定Plugin或Payload字典的一部分。

---

# 八、SQLi、Command Injection、Log4j及OAST等攻擊

## SIEM看到的行為

三日可見：

```text
SQL Injection
Time-based SQL Injection
xp_cmdshell
OS Command Injection
Log4j
OAST／Interactsh
Request Smuggling
Struts RCE
ClassLoader
敏感檔案測試
```

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 632附近 | ScopeSentry可列出Plugin及其Hash與預設Parameter。 |
| 657 | 建立掃描任務。 |
| 693 | 建立掃描模板，指定Module及Plugin Hash。 |
| 701 | 可查詢Vulnerability資產。 |
| 729 | Vulnerability結果包含Request及Response。 |
| 779 | 掃描模組包含VulnerabilityScan。 |

## 吻合判斷

**吻合程度：高，但對應的是ScopeSentry／Plugin掃描能力，不是`api-recon`。**

具體Payload較合理的來源為：

```text
ScopeSentry Plugin
掃描Template
VulnerabilityScan
ARTEX另外調用的自訂工具
```

---

# 九、`api-recon`明確禁止漏洞利用

## Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 41 | Skill只做API及參數面偵察，不是漏洞挖掘或滲透利用階段。 |
| 47 | 禁止SQLi、XSS、越權、爆破、Fuzz、改包攻擊及破壞性操作。 |
| 69 | 禁止以取得真實資料為由進行越權或注入測試。 |

## 正確歸因方式

不可寫成：

```text
api-recon產生SQLi、Log4j、Traversal及OAST攻擊。
```

應寫成：

```text
api-recon負責發現Endpoint、Method及Parameter；
後續具體漏洞Payload較可能由ScopeSentry Plugin、
VulnerabilityScan或ARTEX調用的其他工具產生。
```

---

# 十、跨日保留Endpoint與資產

## SIEM看到的行為

10月14日及10月15日：

```text
來源Alias不同
標的APP_A相同
多個應用Endpoint相同
第二日較快進入深入測試
```

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 99 | `insert_assets`將服務及Endpoint寫入資產庫。 |
| 144 | 批次插入所有已發現的服務及Endpoint，不能遺漏已發現資產。 |
| 657 | 建立掃描任務時可從不同資產來源選擇Target。 |
| 665–669 | 掃描Target可從Asset、RootDomain、Subdomain或UrlScan結果取得。 |
| 680–690 | 可先蒐集資產，再將前一階段結果送往後續模組。 |
| 701 | 資產庫包含Asset、UrlScan、Crawler、DirScanResult及Vulnerability。 |

## 吻合判斷

**吻合程度：中高。**

ARTEX／ScopeSentry具備資產持久化及將前一任務結果交給後續任務的能力，因此第二日沿用相同Endpoint是合理解釋。

## 判斷限制

SIEM本身不能證明10月15日實際讀取了10月14日的資產紀錄。需要下列資料確認：

```text
ARTEX Task ID
ScopeSentry Task
Asset DB紀錄
Traffic ID
Run ID
```

---

# 十一、換新標的後的技術棧適應

## SIEM看到的行為

### APP_A

```text
Java／Servlet
WEB-INF
JSESSIONID Path Parameter
File Handler
Log4j
Struts
```

### APP_B／APP_C

```text
ASP.NET
web.config
trace.axd
大量POST
登入及驗證碼
RSA Key
SQL Injection
Backup File
```

## 對應Skill原始條文

| 行號 | 原始條文重點 |
|---:|---|
| 35–37 | 探索不同標的的API、Route、Method、Parameter及UI功能。 |
| 75–88 | 靜態及Runtime雙層探索。 |
| 343–590 | Browser操作不同網站功能及表單。 |
| 693 | 依Module及Plugin建立掃描Template。 |
| 779 | URLScan、WebCrawler、URLSecurity、DirScan及VulnerabilityScan。 |

## 吻合判斷

**吻合程度：中高。**

新標的出現不同Endpoint、Method比例及技術棧測試，與ARTEX動態探索及ScopeSentry依模板／Plugin執行後續掃描的架構相容。

## 判斷限制

傳統Scanner也能依技術指紋啟用不同Template，因此這能支持：

```text
具目標適應能力的自動化平台
```

但不能單獨支持：

```text
LLM自主推理並產生攻擊策略
```

---

# 十二、Log與Skill對應總表

| SIEM看到的Log行為 | 對應Skill | 行號 | 吻合程度 | 可下結論 |
|---|---|---:|---:|---|
| HTML、JS Bundle及Chunk取得 | api-recon／playwright-cli | 75–99、135–177、343–405 | 高 | 前端探索流程吻合 |
| 應用專屬API及Route出現 | api-recon | 35–37、53–58、75–88、234–290 | 很高 | API及Runtime探索吻合 |
| Method、Body及Parameter探索 | api-recon | 37、79–80、88、97、178–218、234–269 | 高 | 參數及Runtime分析吻合 |
| 登入、表單、POST及UI功能 | playwright-cli | 25、343–405、406–442、483–519、547–590 | 高 | Browser自動化能力吻合 |
| 通用敏感路徑掃描 | scopesentry | 619–693、701、728、779 | 高 | DirScan／URLSecurity吻合 |
| File Handler被集中測試 | api-recon→scopesentry | 35–37、75–88、657、693、729、779 | 中高 | Endpoint發現後進入掃描流程 |
| SQLi、Log4j、OAST及Traversal | scopesentry／Plugin | 657、693、701、729、779 | 高 | 漏洞Plugin及Template能力吻合 |
| 跨日保存並重用Endpoint | api-recon／scopesentry | 99、144、657、665–690、701 | 中高 | 具資產持久化能力，需Task紀錄確認 |
| 換標的後改變功能及技術測試 | 全部 | 35–37、75–88、343–590、693、779 | 中高 | 具目標適應能力的自動化流程 |
| 將具體漏洞Payload歸因至api-recon | api-recon禁止條文 | 41、47、69 | 不吻合 | 應排除錯誤歸因 |

---

# 十三、SIEM目前能證明的範圍

## 可以確認

- 活動高度自動化；
- 存在Browser、CLI及掃描平台協作；
- 存在前端探索、應用API探索、敏感路徑及漏洞驗證等多個階段；
- Log行為與ARTEX三套Skill的能力分工高度相容；
- 10月14日與10月15日為不同來源、相同標的及部分相同Endpoint；
- 10月16日換成新標的後，Endpoint、Method及技術測試方向隨之改變。

## 目前不能單靠SIEM證明

- 某筆Request一定由哪個Skill或Tool Call產生；
- 某次停頓就是LLM推理；
- 某個Burst就是一次Tool Call批次；
- 某次Path Mutation是模型讀取WAF Block後即時產生；
- 某個Payload是LLM動態生成，而非Plugin固定模板；
- 未知來源只要出現相同Pattern就一定是ARTEX或AI Agent。

---

# 最終結論

三日SIEM Log與`ARTEX_SKILLS_MERGED.md`的對應結果顯示：

```text
前端Bundle及Endpoint探索
→ 對應api-recon

Runtime API、Method及Parameter發現
→ 對應api-recon

Browser、表單及頁面功能操作
→ 對應playwright-cli

敏感路徑、漏洞Plugin及後續掃描
→ 對應scopesentry

資產保存及後續任務續掃
→ 對應insert_assets及ScopeSentry資產／任務流程
```

因此，目前SIEM確實能看到與ARTEX Skill協作流程吻合的蛛絲馬跡，特別是：

```text
前端探索
→ 應用專屬Endpoint出現
→ Browser與CLI／Scanner接手
→ 特定Endpoint集中測試
→ 多種漏洞告警
→ 跨日保留相同標的及Endpoint關係
→ 換標的後改變Method及技術測試方向
```

對已知樣本可寫為：

> 依測試執行資訊，本次活動來源為ARTEX；SIEM所觀察到的前端探索、API及參數發現、Browser自動化、資產保存及後續漏洞掃描，與ARTEX Skills所定義能力高度吻合。

對未知來源則應保守寫為：

> 該活動呈現與ARTEX架構相容的Agent-Like適應式自動化行為，但若缺少ARTEX Run、Task、Worker、Tool Call及Traffic Telemetry，尚不足以僅靠SIEM Pattern確認為ARTEX或AI Agent。
