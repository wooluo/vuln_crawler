# Vulnerability Crawler & Reporter

一个多源漏洞情报聚合工具，能够从多个权威安全数据源爬取漏洞信息，去重后生成结构化报告。支持自定义时间范围查询、多格式输出和自动化定时任务。

## 项目优点

### 核心优势
- **多源数据聚合**：整合CISA、OSCS、奇安信、长亭Rivers和ThreatBook等多个权威漏洞数据源，提供全面的漏洞情报覆盖
- **智能去重**：基于CVE ID和漏洞名称+日期的双重去重机制，确保数据的唯一性和准确性
- **灵活配置**：通过环境变量或参数自定义爬取时间范围、输出目录等，适应不同场景需求
- **报告生成**：自动生成Markdown格式漏洞报告，支持参考链接格式化，便于阅读和分享
- **PoC搜索**：集成GitHub PoC/EXP搜索功能，辅助漏洞验证和安全评估
- **定时任务**：支持周期性自动爬取（通过GitHub Actions实现），实现漏洞情报的持续更新

### 技术特点
- **模块化设计**：采用清晰的模块化架构，便于维护和扩展
- **并行处理**：使用多线程技术提高数据爬取效率
- **友好界面**：提供直观的图形界面，降低使用门槛
- **多格式输出**：支持JSON、CSV等多种数据格式导出
- **错误处理**：完善的错误处理机制，确保系统稳定性
- **代理支持**：支持配置代理，解决网络访问问题

### 二开优势
- **持续维护**：基于原项目进行二次开发，持续更新和优化
- **功能扩展**：根据实际需求添加新功能和数据源
- **性能优化**：改进爬取策略和数据处理逻辑，提高系统性能
- **用户体验**：优化界面设计和交互流程，提升用户体验

## 核心功能

- **多源数据聚合**：整合CISA、OSCS、奇安信、长亭Rivers和ThreatBook等多个权威漏洞数据源
- **智能去重**：基于CVE ID和漏洞名称+日期的双重去重机制
- **灵活配置**：通过环境变量或参数自定义爬取时间范围、输出目录等
- **报告生成**：自动生成Markdown格式漏洞报告，支持参考链接格式化
- **PoC搜索**：集成GitHub PoC/EXP搜索功能，辅助漏洞验证
- **定时任务**：支持周期性自动爬取（通过GitHub Actions实现）

## 支持数据源

| 数据源 | 说明 | 数据类型 |
|--------|------|----------|
| CISA | 美国网络安全与基础设施安全局 | 高危漏洞公告 |
| OSCS | 国家信息安全漏洞库 | 漏洞情报 |
| 奇安信 | 奇安信威胁情报中心 | 漏洞预警 |
| 长亭Rivers | 长亭科技漏洞数据库 | 详细漏洞信息 |
| ThreatBook | 微步在线威胁情报 | 漏洞风险评级 |

## 快速开始

### 环境要求
- Python 3.9+ 
- 依赖包：见requirements.txt
- 网络连接（部分数据源可能需要代理）

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/wooluo/vuln_crawler.git
cd vuln_crawler

# 创建虚拟环境
python -m venv .venv
# 激活虚拟环境
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 基本使用

#### 1. 图形界面模式（推荐）
```bash
python main.py
```

#### 2. 命令行模式
```bash
# 爬取最近3天漏洞并生成报告
python vuln_scraper.py

# 指定爬取时间范围（例如7天）
DAYS_BACK=7 python vuln_scraper.py

# 搜索特定漏洞信息
python vuln_search.py "CVE-2023-48795"
```

#### 3. 快速导出漏洞数据
```bash
# 导出JSON格式数据
python quick_dump.py --format json

# 导出CSV格式数据
python quick_dump.py --format csv
```

## 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| DAYS_BACK | 爬取时间范围（天） | 3 |
| OUTPUT_DIR | 报告输出目录 | vulnerability_reports |
| GITHUB_TOKEN | GitHub API访问令牌（用于PoC搜索） | 无 |

### 自定义配置文件
创建`config.json`文件进行高级配置：
```json
{
  "proxy": "http://127.0.0.1:7890",
  "data_sources": {
    "cisa": true,
    "oscs": true,
    "qianxin": true,
    "changtin": true,
    "threatbook": false
  },
  "report": {
    "include_poc": true,
    "severity_filter": ["critical", "high"]
  }
}
```

## 项目结构

```
vuln_crawler/
├── .github/workflows/      # GitHub Actions配置
├── changtin.py             # 长亭Rivers数据源
├── cisa.py                 # CISA数据源
├── config_io.py            # 配置文件处理
├── main.py                 # GUI入口
├── models.py               # 漏洞数据模型
├── oscs.py                 # OSCS数据源
├── poc_fetcher.py          # GitHub PoC搜索
├── qianxin.py              # 奇安信数据源
├── quick_dump.py           # 快速导出工具
├── requirements.txt        # 依赖列表
├── threatbook.py           # ThreatBook数据源
├── utils.py                # 工具函数
├── vuln_scraper.py         # 核心爬取逻辑
└── vuln_search.py          # 漏洞搜索工具
```

## 自动化任务

项目包含GitHub Actions配置，可实现定时自动爬取：
1. Fork本仓库
2. 在仓库Settings → Secrets中添加必要的环境变量
3. 启用.github/workflows/vuln_crawl.yml工作流

默认配置为每天UTC 0点执行爬取，结果会自动提交到仓库的`reports`分支。

## 常见问题

### Q: 部分数据源爬取失败？
A: 检查网络连接，部分数据源可能需要科学上网。可在配置文件中设置代理。

### Q: 如何获取GitHub Token？
A: 在GitHub → Settings → Developer settings → Personal access tokens创建，只需勾选`public_repo`权限。

### Q: 报告中的参考链接格式异常？
A: 确保所有数据源的reference字段均返回列表类型，可通过`utils.py`中的`format_markdown`函数调整格式。

## 许可证
[MIT](LICENSE)
