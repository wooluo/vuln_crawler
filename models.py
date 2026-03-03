from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

# 严重程度常量
SEVERITY_LEVELS = {
    "严重": 5,
    "极危": 5,
    "高危": 4,
    "高风险": 4,
    "中危": 3,
    "中风险": 3,
    "低危": 2,
    "低风险": 2,
    "信息": 1
}

@dataclass
class VulnItem:
    name: str
    cve: Optional[str] = None
    date: str = ""  # YYYY-MM-DD
    severity: str = ""
    tags: Optional[str] = None
    source: str = ""
    description: Optional[str] = None
    reference: Optional[List[str]] = field(default_factory=list)

    def display_block(self) -> str:
        """生成漏洞信息的文本展示"""
        ref_str = "\n".join(self.reference) if self.reference else ""
        return (
            f"【漏洞名称】{self.name}\n"
            f"【CVE编号】{self.cve or '无'}\n"
            f"【漏洞披露时间】{self.date or '未知'}\n"
            f"【漏洞等级】{self.severity or '未分级'}\n"
            f"【漏洞标签】{self.tags or '无'}\n"
            f"【漏洞来源】{self.source or '未知'}\n"
            f"【漏洞描述】{self.description or '无描述'}\n"
            f"【参考链接】{ref_str}\n"
        )

    def to_dict(self) -> Dict[str, Any]:
        """将对象转换为字典"""
        return {
            "name": self.name,
            "cve": self.cve,
            "date": self.date,
            "severity": self.severity,
            "tags": self.tags,
            "source": self.source,
            "description": self.description,
            "reference": self.reference
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnItem':
        """从字典创建对象"""
        return cls(
            name=data.get("name", ""),
            cve=data.get("cve"),
            date=data.get("date", ""),
            severity=data.get("severity", ""),
            tags=data.get("tags"),
            source=data.get("source", ""),
            description=data.get("description"),
            reference=data.get("reference", [])
        )

    def get_severity_level(self) -> int:
        """获取严重程度的数值级别"""
        return SEVERITY_LEVELS.get(self.severity, 0)

    def is_valid(self) -> bool:
        """检查漏洞信息是否有效"""
        return bool(self.name) and bool(self.date)

    def format_date(self, format_str: str = "%Y-%m-%d") -> str:
        """格式化日期"""
        try:
            if self.date:
                date_obj = datetime.strptime(self.date, "%Y-%m-%d")
                return date_obj.strftime(format_str)
            return ""
        except ValueError:
            return self.date

    def __str__(self) -> str:
        """友好的字符串表示"""
        cve_part = f" ({self.cve})" if self.cve else ""
        return f"{self.name}{cve_part} - {self.severity} - {self.date}"

    def __eq__(self, other: object) -> bool:
        """对象比较"""
        if not isinstance(other, VulnItem):
            return NotImplemented
        return self.cve == other.cve and self.name == other.name

    def __hash__(self) -> int:
        """哈希方法，支持作为字典键"""
        return hash((self.cve or "" , self.name))
