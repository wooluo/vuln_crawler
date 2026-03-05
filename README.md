# 漏洞情报聚合系统

一个基于开源项目二次开发的多源漏洞情报聚合工具，能够从多个权威安全数据源爬取漏洞信息，去重后生成结构化报告。支持自定义时间范围查询、多格式输出和现代化图形界面。

## 项目特点

### 核心优势

- **多源数据聚合**：整合CISA、OSCS、奇安信、长亭Rivers和ThreatBook等多个权威漏洞数据源，实现全方位漏洞情报覆盖
- **现代化GUI界面**：基于PyQt6开发的图形界面，采用科技感设计风格，支持实时数据展示和交互式操作
- **智能数据处理**：基于CVE ID和漏洞名称+日期的双重去重机制，确保数据质量
- **灵活配置管理**：通过环境变量、配置文件或GUI界面自定义爬取时间范围、输出目录、代理设置等
- **多格式报告生成**：自动生成Markdown格式漏洞报告，支持参考链接格式化和结构化数据展示
- **PoC搜索集成**：集成GitHub PoC/EXP搜索功能，辅助漏洞验证和利用分析
- **定时任务支持**：支持周期性自动爬取（通过GitHub Actions实现），实现自动化运维
- **路径自定义**：报告查看器支持自定义报告路径，方便管理不同来源的漏洞报告
- **实时数据测试**：内置数据源测试功能，可快速验证各数据源的可用性和数据质量

### 技术亮点

- **模块化架构**：清晰的代码组织结构，各数据源独立封装，易于维护和扩展
- **异步处理**：多线程并发请求，提高数据获取效率
- **错误重试机制**：完善的异常处理和重试逻辑，确保数据获取的稳定性
- **现代化UI设计**：采用科技感配色方案，统一的白色字体，良好的视觉体验
- **响应式布局**：界面元素自适应窗口大小，提供良好的用户体验

## 支持数据源

| 数据源 | 说明 | 数据类型 | 特点 |
|--------|------|----------|------|
| CISA | 美国网络安全与基础设施安全局 | 高危漏洞公告 | 权威性高，覆盖面广 |
| OSCS | 国家信息安全漏洞库 | 漏洞情报 | 国内权威，更新及时 |
| 奇安信 | 奇安信威胁情报中心 | 漏洞预警 | 专业分析，风险评估 |
| 长亭Rivers | 长亭科技漏洞数据库 | 详细漏洞信息 | 技术细节丰富 |
| ThreatBook | 微步在线威胁情报 | 漏洞风险评级 | 风险评估准确 |

## 快速开始

### 环境要求
- Python 3.9+ 
- 依赖包：见requirements.txt
- 网络连接（部分数据源可能需要代理）

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/your-username/vuln_crawler.git
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

#### 3. 报告查看器
```bash
# 启动漏洞报告查看器
python report_viewer.py
```

#### 4. 快速导出漏洞数据
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
│   └── vuln_crawl.yml   # 自动化爬取工作流
├── changtin.py             # 长亭Rivers数据源
├── cisa.py                 # CISA数据源
├── config_io.py            # 配置文件处理
├── main.py                 # GUI主程序入口
├── models.py               # 漏洞数据模型
├── oscs.py                 # OSCS数据源
├── poc_fetcher.py          # GitHub PoC搜索
├── qianxin.py              # 奇安信数据源
├── quick_dump.py           # 快速导出工具
├── report_viewer.py        # 漏洞报告查看器
├── requirements.txt        # 依赖列表
├── threatbook.py           # ThreatBook数据源
├── utils.py                # 工具函数
├── vuln_scraper.py         # 核心爬取逻辑
└── vuln_search.py          # 漏洞搜索工具
```

### 核心模块说明

#### 数据源模块
- `changtin.py` - 长亭Rivers数据源接口
- `cisa.py` - CISA数据源接口
- `oscs.py` - OSCS数据源接口
- `qianxin.py` - 奇安信数据源接口
- `threatbook.py` - ThreatBook数据源接口

#### 核心功能模块
- `main.py` - 图形界面主程序，提供完整的GUI操作界面
- `vuln_scraper.py` - 核心爬取逻辑，协调多数据源数据获取
- `vuln_search.py` - 漏洞搜索工具，支持关键词和CVE搜索
- `report_viewer.py` - 漏洞报告查看器，提供现代化的报告浏览界面

#### 辅助模块
- `models.py` - 漏洞数据模型定义
- `utils.py` - 工具函数集合
- `config_io.py` - 配置文件读写
- `poc_fetcher.py` - GitHub PoC搜索功能

#### 工具模块
- `quick_dump.py` - 快速数据导出工具

## 功能特性详解
