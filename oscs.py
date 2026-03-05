# oscs.py
"""
OSCS 开源安全情报

新地址:
    https://www.oscs1024.com/cm  (漏洞情报页面)
    https://www.oscs1024.com/hd/[MPS编号] (漏洞详情页面)

功能:
    - fetch_oscs(date)     —— 按日期抓取 (高危/严重)
    - search_oscs(keyword) —— 关键词 / CVE 搜索
"""

from typing import List
import random, time, re
from models import VulnItem
from utils import _session

CM_PAGE = "https://www.oscs1024.com/cm"
LEVEL_OK = {"严重", "高危"}        # 要“中危”也算就加进去

# ------------------------- 内部通用函数 -------------------------

def _parse_cm_page() -> List[dict]:
    """
    解析漏洞情报页面，提取漏洞信息
    """
    try:
        r = _session.get(CM_PAGE, timeout=8)
        r.raise_for_status()
        content = r.text
        
        # 提取漏洞信息 - 匹配表格结构
        # 匹配模式：公开时间 标题 风险等级
        pattern = r'(\d{4}-\d{2}-\d{2})[^>]*>(.*?)<[^>]*>(严重|高危|中危|低危)'  
        matches = re.findall(pattern, content, re.DOTALL)
        
        vulns = []
        for match in matches:
            date_str, name, severity = match
            # 清理标题中的空白字符
            name = re.sub(r'\s+', ' ', name).strip()
            if severity in LEVEL_OK:
                vulns.append({
                    "title": name,
                    "level": severity,
                    "public_time": f"{date_str}T00:00:00",
                    "url": CM_PAGE
                })
        
        return vulns
    except Exception as e:
        print(f"[OSCS] 解析页面失败: {e}")
        # 打印部分页面内容用于调试
        print("[OSCS] 页面内容前 500 字符:")
        print(content[:500])
        
        # 出错时返回空列表
        return []

# --------------------------- 搜索 ---------------------------

def search_oscs(keyword: str) -> List[VulnItem]:
    """
    关键词搜索:
        - 以 'CVE-' 开头 (忽略大小写) → 精确匹配 cve_id
        - 否则对 title 做包含匹配 (不区分大小写)
    仅保留 level ∈ LEVEL_OK
    """
    vulns: List[VulnItem] = []
    is_cve = keyword.lower().startswith("cve-")
    
    # 解析漏洞情报页面
    rows = _parse_cm_page()
    
    for row in rows:
        if is_cve:
            # 简单匹配，实际可能需要更复杂的逻辑
            if keyword.lower() in row["title"].lower():
                vulns.append(
                    VulnItem(
                        name=row["title"],
                        cve=None,  # 从页面无法直接获取 CVE
                        date=row["public_time"].split("T")[0],
                        severity=row["level"],
                        tags=None,
                        source="OSCS",
                        description=None,  # 从页面无法直接获取描述
                        reference=[row["url"]] if row["url"] else None,
                    )
                )
        else:
            if keyword.lower() in row["title"].lower():
                vulns.append(
                    VulnItem(
                        name=row["title"],
                        cve=None,
                        date=row["public_time"].split("T")[0],
                        severity=row["level"],
                        tags=None,
                        source="OSCS",
                        description=None,
                        reference=[row["url"]] if row["url"] else None,
                    )
                )
    
    return vulns

# --------------------------- 按日期抓取 ---------------------------

def fetch_oscs(date: str) -> List[VulnItem]:
    """
    返回发布日期 == <date> 且 level ∈ LEVEL_OK 的列表
    """
    vulns: List[VulnItem] = []
    
    # 解析漏洞情报页面
    rows = _parse_cm_page()
    
    for row in rows:
        pub_date = row["public_time"].split("T")[0]
        if pub_date != date:
            continue
        if row["level"] not in LEVEL_OK:
            continue

        vulns.append(
            VulnItem(
                name=row["title"],
                cve=None,  # 从页面无法直接获取 CVE
                date=pub_date,
                severity=row["level"],
                tags=None,
                source="OSCS",
                description=None,  # 从页面无法直接获取描述
                reference=[row["url"]] if row["url"] else None,
            )
        )

    return vulns
