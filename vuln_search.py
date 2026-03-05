# vuln_search.py
"""
统一关键词 / CVE 搜索入口
---------------------------------
依赖各数据源的 search_xxx(keyword) 函数，而不是 fetch_xxx(date)。
这样就不会再把空日期传给日期接口，避免 isoformat 解析报错。
"""

import threading
from typing import List, Optional, Tuple
from models import VulnItem
import changtin, oscs, qianxin, threatbook, cisa

# 仅放“搜索入口” ↓↓↓
SEARCHERS = {
    "长亭":       changtin.search_changtin,
    "OSCS":      oscs.search_oscs,
    "奇安信":     qianxin.search_qianxin,
    "ThreatBook": threatbook.search_threatbook,
    "CISA":      cisa.search_cisa,
}

def _calculate_relevance(vuln: VulnItem, keyword: str) -> int:
    """
    计算漏洞与关键词的相关度
    ------------------------------------------------
    返回相关度分数，分数越高越相关
    """
    score = 0
    kw_lower = keyword.lower()
    
    # CVE 精确匹配，最高优先级
    if vuln.cve and kw_lower == vuln.cve.lower():
        return 100
    
    # 漏洞名称匹配
    if vuln.name:
        name_lower = vuln.name.lower()
        if kw_lower == name_lower:
            score += 80
        elif kw_lower in name_lower:
            # 关键词在名称中的位置越靠前，分数越高
            position = name_lower.find(kw_lower)
            score += 60 - position // 5  # 位置越靠前，扣分越少
    
    # 描述匹配
    if vuln.description:
        desc_lower = vuln.description.lower()
        if kw_lower in desc_lower:
            score += 30
    
    # 标签匹配
    if vuln.tags:
        tags_lower = vuln.tags.lower()
        if kw_lower in tags_lower:
            score += 20
    
    return score

def _deduplicate_results(results: List[VulnItem]) -> List[VulnItem]:
    """
    去重搜索结果
    ------------------------------------------------
    根据 CVE 和名称组合去重
    """
    seen = set()
    unique_results = []
    
    for vuln in results:
        # 使用 CVE 和名称的组合作为唯一标识
        key = (vuln.cve or "", vuln.name)
        if key not in seen:
            seen.add(key)
            unique_results.append(vuln)
    
    return unique_results

def search_vulns(
    keyword: str,
    sources: Optional[List[str]] = None,
    max_workers: int = 5,
) -> List[VulnItem]:
    """
    根据 CVE 或漏洞名称搜索漏洞（不限制日期）
    ------------------------------------------------
    * CVE：忽略大小写 **精确匹配**（keyword 以 'CVE-' 开头）
    * 名称：忽略大小写 **模糊包含**
    * 描述：忽略大小写 **模糊包含**
    * 标签：忽略大小写 **模糊包含**
    * 若 sources 为 None → 查询 SEARCHERS 全部源
    * 结果按相关度排序并去重
    """
    if not keyword:
        return []
        
    if sources is None:
        sources = SEARCHERS.keys()

    results: List[VulnItem] = []
    mutex = threading.Lock()
    threads = []

    def _task(name: str, fn):
        try:
            items = fn(keyword)             # 各源的搜索函数
            with mutex:
                results.extend(items)
        except Exception as e:
            print(f"Error searching {name}: {e}")

    for name in sources:
        fn = SEARCHERS.get(name)
        if not fn:
            print(f"[WARN] 未找到搜索函数: {name}")
            continue
        t = threading.Thread(target=_task, args=(name, fn), daemon=True)
        threads.append(t)
        t.start()

        # 控制并发数，避免瞬间开太多线程
        while len([th for th in threads if th.is_alive()]) >= max_workers:
            for th in threads:
                th.join(timeout=0.1)

    # 等待剩余线程
    for t in threads:
        t.join()
    
    # 去重
    unique_results = _deduplicate_results(results)
    
    # 计算相关度并排序
    scored_results = [(vuln, _calculate_relevance(vuln, keyword)) for vuln in unique_results]
    scored_results.sort(key=lambda x: x[1], reverse=True)
    
    # 返回排序后的结果
    return [vuln for vuln, score in scored_results]


def search_vulns_with_scores(
    keyword: str,
    sources: Optional[List[str]] = None,
    max_workers: int = 5,
) -> List[Tuple[VulnItem, int]]:
    """
    搜索漏洞并返回带相关度分数的结果
    ------------------------------------------------
    返回格式：[(VulnItem, 相关度分数), ...]
    """
    if not keyword:
        return []
        
    results = search_vulns(keyword, sources, max_workers)
    return [(vuln, _calculate_relevance(vuln, keyword)) for vuln in results]
