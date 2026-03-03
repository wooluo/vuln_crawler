import logging
import datetime as _dt
import time
import random
from typing import Dict, List, Callable, Optional, Any, Tuple
import requests
from models import VulnItem, SEVERITY_LEVELS, SEVERITY_LEVELS

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------- HTTP 会话 ----------------
_session = requests.Session()
_session.headers.update({
    "User-Agent": "Mozilla/5.0 vuln-crawler/1.1 (+https://example.com)",
    "Accept": "application/json, text/plain, */*",
    "Connection": "close",
})

# ---------------- 网络请求工具 ----------------
def request_with_retry(
    method: str,
    url: str,
    max_retries: int = 3,
    backoff_factor: float = 0.5,
    **kwargs
) -> Optional[requests.Response]:
    """
    带重试机制的网络请求
    
    Args:
        method: 请求方法（GET, POST等）
        url: 请求URL
        max_retries: 最大重试次数
        backoff_factor: 退避因子
        **kwargs: 其他请求参数
        
    Returns:
        响应对象或None
    """
    for attempt in range(max_retries):
        try:
            response = _session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = backoff_factor * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(f"Request failed (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time:.2f}s...")
                time.sleep(wait_time)
            else:
                logger.error(f"Request failed after {max_retries} attempts: {e}")
                return None

# ---------------- 去重合并 ----------------
Fetcher = Callable[[str], List[VulnItem]]

def fetch_all(target_date: str, fetchers: List[Fetcher]) -> List[VulnItem]:
    """
    从多个数据源获取漏洞并去重
    
    Args:
        target_date: 目标日期（YYYY-MM-DD）
        fetchers: 抓取函数列表
        
    Returns:
        去重后的漏洞列表
    """
    seen: Dict[str, VulnItem] = {}
    total_items = 0
    
    for fn in fetchers:
        try:
            items = fn(target_date)
            total_items += len(items)
            logger.info(f"[{fn.__name__}] {len(items)} item(s)")
        except Exception as e:
            logger.error(f"[{fn.__name__}] ERROR → {e}")
            continue

        for it in items:
            key = it.cve or f"{it.name}_{it.date}"
            seen.setdefault(key, it)

    logger.info(f"Total items: {total_items}, Unique items: {len(seen)}")
    return list(seen.values())

# ---------------- 代理设置 ----------------
def _normalize(url: Optional[str], default_scheme: str) -> Optional[str]:
    """
    规范化代理URL
    
    若 url 为 '127.0.0.1:7890' → 自动补 'http://127.0.0.1:7890'
    若已带 scheme（http://、https://、socks5://…）则原样返回
    """
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        url = f"{default_scheme}://{url}"
    return url

def set_proxy(http_url: Optional[str] = None,
              https_url: Optional[str] = None) -> None:
    """
    运行时更新代理:
      http_url  —— 形如 '127.0.0.1:7890' 或完整 'http://...' / 'socks5://...'
      https_url —— 同上
    传 None / '' 表示清空对应协议代理
    """
    http_url  = _normalize(http_url,  "http")
    https_url = _normalize(https_url, "http")   # HTTPS 代理常用 http CONNECT 隧道

    proxies = _session.proxies.copy()
    if http_url:
        proxies['http'] = http_url
    else:
        proxies.pop('http', None)

    if https_url:
        proxies['https'] = https_url
    else:
        proxies.pop('https', None)

    _session.proxies = proxies
    logger.info(f"Proxy updated: http={http_url}, https={https_url}")

# ---------------- 小工具 ----------------
def today() -> str:
    """获取今天的日期字符串（YYYY-MM-DD）"""
    return _dt.date.today().isoformat()

def format_date(date_obj: _dt.date, format_str: str = "%Y-%m-%d") -> str:
    """格式化日期对象"""
    return date_obj.strftime(format_str)

def parse_date(date_str: str, format_str: str = "%Y-%m-%d") -> Optional[_dt.date]:
    """解析日期字符串"""
    try:
        return _dt.datetime.strptime(date_str, format_str).date()
    except ValueError:
        return None

def get_date_range(start_date: str, end_date: str) -> List[str]:
    """
    获取日期范围内的所有日期
    
    Args:
        start_date: 开始日期（YYYY-MM-DD）
        end_date: 结束日期（YYYY-MM-DD）
        
    Returns:
        日期字符串列表
    """
    start = parse_date(start_date)
    end = parse_date(end_date)
    
    if not start or not end:
        return []
    
    dates = []
    current = start
    while current <= end:
        dates.append(current.isoformat())
        current += _dt.timedelta(days=1)
    
    return dates

# ---------------- 数据处理 ----------------
def sort_vulns_by_severity(vulns: List[VulnItem]) -> List[VulnItem]:
    """
    按严重程度排序漏洞
    
    Args:
        vulns: 漏洞列表
        
    Returns:
        排序后的漏洞列表
    """
    return sorted(vulns, key=lambda v: v.get_severity_level(), reverse=True)

def filter_vulns_by_severity(vulns: List[VulnItem], min_severity: int) -> List[VulnItem]:
    """
    按严重程度过滤漏洞
    
    Args:
        vulns: 漏洞列表
        min_severity: 最小严重程度级别
        
    Returns:
        过滤后的漏洞列表
    """
    return [v for v in vulns if v.get_severity_level() >= min_severity]

# ---------------- Markdown 格式化 ----------------
def format_markdown(vuln: VulnItem, index: int) -> str:
    """将漏洞信息格式化为Markdown字符串"""
    md = [f"### {index}. {vuln.name}"]
    if vuln.cve:
        md.append(f"- **CVE ID**: [{vuln.cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve})")
    md.append(f"- **发布日期**: {vuln.date or '未知'}")
    md.append(f"- **严重程度**: {vuln.severity or '未分级'}")
    md.append(f"- **来源**: {vuln.source or '未知'}")
    if vuln.tags:
        md.append(f"- **标签**: {vuln.tags}")
    md.append(f"- **漏洞描述**\n{vuln.description or '无描述'}")
    if vuln.reference:
        md.append("- **参考链接**")
        # 确保reference始终是列表
        references = vuln.reference if isinstance(vuln.reference, list) else [vuln.reference]
        for ref in references:
            if isinstance(ref, str) and ref.startswith(('http://', 'https://')):
                # 缩短长链接
                display_ref = ref[:50] + "..." if len(ref) > 50 else ref
                md.append(f"- [{display_ref}]({ref})")
            elif isinstance(ref, str):
                md.append(f"- {ref}")
    return '\n'.join(md)

def generate_markdown_report(vulns: List[VulnItem], title: str = "漏洞报告") -> str:
    """
    生成漏洞报告的Markdown内容
    
    Args:
        vulns: 漏洞列表
        title: 报告标题
        
    Returns:
        Markdown格式的报告内容
    """
    # 按严重程度排序
    sorted_vulns = sort_vulns_by_severity(vulns)
    
    # 生成报告
    md = [
        f"# {title}",
        f"生成时间: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"漏洞总数: {len(vulns)}",
        "",
        "## 漏洞列表"
    ]
    
    for i, vuln in enumerate(sorted_vulns, 1):
        md.append("")
        md.append(format_markdown(vuln, i))
        md.append("---")
    
    return '\n'.join(md)
