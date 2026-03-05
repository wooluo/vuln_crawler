# threatbook.py
"""
ThreatBook 漏洞首页

接口
----
https://x.threatbook.com/v5/node/vul_module/homePage  (GET, JSON)

功能
----
- fetch_threatbook(date)   —— 按日期过滤 premium + highRisk 列表
- search_threatbook(keyword) —— 关键词 / CVE 搜索
"""

from typing import List, Optional, Dict
import random, time, logging
from models import VulnItem
from utils import _session, request_with_retry

# 配置日志
logger = logging.getLogger(__name__)

API = "https://x.threatbook.com/v5/node/vul_module/homePage"

_headers = {
    "Referer": "https://x.threatbook.com/",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0 vuln-crawler/1.1 (+https://example.com)",
    # 如需访问登录后条目，可在 GUI 中通过 set_cookie() 注入
    # "Cookie": "TBOOK_SESSIONID=xxxxxxxxxxxxxxxx;",
}

# 缓存机制
_cache: Dict[str, tuple] = {}  # 缓存格式: {cache_key: (timestamp, data)}
CACHE_TTL = 300  # 缓存过期时间（秒）

# ------------------- GUI 用 Cookie 动态注入 -------------------

def set_cookie(raw: str) -> None:
    """
    在 GUI 中粘贴完整 Cookie 后调用；传空串则清空
    """
    raw = raw.strip()
    if raw:
        _headers["Cookie"] = raw
        logger.info("ThreatBook Cookie 已设置")
    else:
        _headers.pop("Cookie", None)
        logger.info("ThreatBook Cookie 已清空")

# --------------------- 辅助解析为 VulnItem ---------------------

def _to_item(it: dict) -> Optional[VulnItem]:
    """
    将 ThreatBook API 返回的漏洞数据转换为 VulnItem 对象
    """
    try:
        # 尝试获取时间戳字段
        ts = it.get("vuln_update_time") or it.get("vulnPublishTime")
        if not ts:
            logger.debug(f"跳过无时间戳的漏洞: {it.get('vuln_name_zh', '未知漏洞')}")
            return None
        
        # 构建 VulnItem 对象
        return VulnItem(
            name=it.get("vuln_name_zh") or it.get("vulnNameZh") or it.get("title", "未知漏洞"),
            cve=it.get("id"),
            date=ts[:10],                       # 仅取 'YYYY-MM-DD'
            severity=it.get("riskLevel") or "高风险",
            tags=None,
            source="ThreatBook",
            description=None,
            reference=None,
        )
    except Exception as e:
        logger.error(f"解析漏洞数据失败: {e}")
        return None

# --------------------- 获取首页数据 ---------------------

def _fetch_homepage(retry: int = 3) -> dict:
    """
    GET homePage 接口，带退避重试；成功返回 .json()['data']
    使用缓存机制减少重复请求
    """
    # 检查缓存
    current_time = time.time()
    cache_key = "homepage"
    
    if cache_key in _cache:
        cache_time, cached_data = _cache[cache_key]
        if current_time - cache_time < CACHE_TTL:
            logger.info("使用缓存的 ThreatBook 数据")
            return cached_data
    
    # 缓存过期或不存在，重新请求
    logger.info("获取 ThreatBook 首页数据...")
    
    try:
        response = request_with_retry("GET", API, headers=_headers, timeout=8)
        if response:
            data = response.json().get("data", {})
            # 更新缓存
            _cache[cache_key] = (current_time, data)
            logger.info(f"成功获取 ThreatBook 数据，缓存有效期 {CACHE_TTL} 秒")
            return data
    except Exception as e:
        logger.error(f"获取 ThreatBook 数据失败: {e}")
    
    return {}

# ------------------------ 按日期抓取 ------------------------

def fetch_threatbook(date: str) -> List[VulnItem]:
    """
    返回 vuln_update_time 以 <date> 开头的 premium + highRisk 条目
    """
    logger.info(f"获取 ThreatBook {date} 的漏洞数据...")
    
    data = _fetch_homepage()
    vulns: List[VulnItem] = []

    # 遍历 premium 和 highRisk 列表
    for key in ("premium", "highRisk"):
        items = data.get(key, [])
        logger.debug(f"{key} 列表包含 {len(items)} 个漏洞")
        
        for it in items:
            item = _to_item(it)
            if item and item.date == date:
                vulns.append(item)

    logger.info(f"找到 {len(vulns)} 个 {date} 的 ThreatBook 漏洞")
    return vulns

# --------------------- 关键词 / CVE 搜索 ---------------------

def search_threatbook(keyword: str) -> List[VulnItem]:
    """
    关键词搜索：
      - 以 'CVE-' 开头 → 精确匹配 id 字段
      - 否则 → 名称模糊匹配（大小写不敏感）
    搜索范围仅限 homePage 中的 premium + highRisk
    """
    logger.info(f"搜索 ThreatBook 漏洞: {keyword}")
    
    data = _fetch_homepage()
    vulns: List[VulnItem] = []

    kw_lower = keyword.lower()
    is_cve = kw_lower.startswith("cve-")

    # 遍历 premium 和 highRisk 列表
    for key in ("premium", "highRisk"):
        for it in data.get(key, []):
            item = _to_item(it)
            if not item:
                continue

            # 搜索逻辑
            if is_cve:
                if (item.cve or "").lower() == kw_lower:
                    vulns.append(item)
            else:
                if kw_lower in item.name.lower():
                    vulns.append(item)

    logger.info(f"找到 {len(vulns)} 个匹配 '{keyword}' 的 ThreatBook 漏洞")
    return vulns
