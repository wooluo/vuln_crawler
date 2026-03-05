import os
import time
import json
from datetime import datetime, timedelta
from utils import logger, format_markdown
from cisa import fetch_cisa
from oscs import fetch_oscs
from qianxin import fetch_qianxin
from threatbook import fetch_threatbook
from changtin import fetch_changtin

class VulnScraper:
    def __init__(self, days_back=None):
        self.output_dir = os.getenv('OUTPUT_DIR', 'vulnerability_reports')
        
        # 允许通过环境变量或参数设置回溯天数，默认3天
        try:
            self.days_back = int(os.getenv('DAYS_BACK', days_back or 3))
            if self.days_back < 1:
                raise ValueError("回溯天数必须为正整数")
        except ValueError as e:
            logger.warning(f"无效的回溯天数设置: {e}, 使用默认值3天")
            self.days_back = 20
        
        self.start_date = (datetime.now() - timedelta(days=self.days_back)).strftime("%Y-%m-%d")
        self.end_date = datetime.now().strftime("%Y-%m-%d")
        
        self.vuln_sources = {
            "CISA": fetch_cisa,
            "OSCS": fetch_oscs,
            "Qianxin": fetch_qianxin,
            "ThreatBook": fetch_threatbook,
            "Changtin": fetch_changtin
        }
        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info(f"漏洞信息爬取配置: 日期范围从 {self.start_date} 到 {self.end_date} (共{self.days_back}天)")



    def fetch_all_vulns(self):
        """从所有数据源获取指定日期范围内的漏洞信息"""
        all_vulns = {}
        current_date = datetime.strptime(self.start_date, "%Y-%m-%d").date()
        end_date = datetime.now().date()
        
        # 遍历日期范围内的每一天
        while current_date <= end_date:
            target_date = current_date.strftime("%Y-%m-%d")
            logger.info(f"开始处理日期: {target_date}")
            
            for source_name, fetcher in self.vuln_sources.items():
                try:
                    logger.info(f"从 {source_name} 获取 {target_date} 的漏洞信息")
                    vulns = fetcher(target_date)
                    
                    if vulns:
                        if source_name not in all_vulns:
                            all_vulns[source_name] = []
                        all_vulns[source_name].extend(vulns)
                        logger.info(f"成功获取 {source_name} {target_date} 漏洞信息 {len(vulns)} 条")
                    else:
                        logger.warning(f"未获取到 {source_name} {target_date} 的漏洞信息")
                except Exception as e:
                    logger.error(f"获取 {source_name} {target_date} 漏洞信息失败: {str(e)}")
                
                # 添加延迟避免请求过于频繁
                time.sleep(2)
            
            current_date += timedelta(days=1)
        
        # 去重处理
        for source_name in all_vulns:
            seen = {}
            unique_vulns = []
            for vuln in all_vulns[source_name]:
                key = vuln.cve or f"{vuln.name}_{vuln.date}"
                if key not in seen:
                    seen[key] = True
                    unique_vulns.append(vuln)
            all_vulns[source_name] = unique_vulns
            logger.info(f"{source_name} 去重后漏洞数量: {len(unique_vulns)}")
        
        return all_vulns

    def generate_markdown_report(self, vulns, report_date=None):
        if not report_date:
            report_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

        """生成Markdown格式的漏洞报告"""

        md_content = f"# 漏洞情报报告 - {report_date}\n\n"
        md_content += f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md_content += "## 目录\n"

        # 添加目录
        for source_name in vulns.keys():
            md_content += f"- [{source_name}](#{source_name.lower()})\n"
        md_content += "\n---\n"

        # 生成漏洞汇总表格
        md_content += "## 漏洞汇总表格\n\n"
        md_content += "| ID | CVE ID | 漏洞名称 | 严重程度 | 发布日期 | 来源 | 参考链接 |\n"
        md_content += "|-----|--------|----------|----------|----------|------|----------|\n"

        all_vulns_list = []
        for source_name, vuln_list in vulns.items():
            all_vulns_list.extend(vuln_list)

        # 按严重程度和日期排序
        sorted_all_vulns = sorted(all_vulns_list, key=lambda x: (getattr(x, 'severity', 'medium') or 'medium', x.date), reverse=True)

        for idx, vuln in enumerate(sorted_all_vulns, 1):
            cve_id = vuln.cve or "-"
            # 处理参考链接
            references = []
            if vuln.reference:
                if isinstance(vuln.reference, list):
                    references = vuln.reference
                else:
                    references = [vuln.reference]
            ref_links = []
            for ref in references[:3]:  # 最多显示3个链接
                if isinstance(ref, str) and ref.startswith(('http://', 'https://')):
                    ref_links.append(f"[{ref[:50]}...]({ref})")
                else:
                    ref_links.append(str(ref)[:50] + "...") if len(str(ref)) > 50 else str(ref)
            ref_str = '<br>'.join(ref_links) if ref_links else "-"

            # 截断过长的漏洞名称
            name = vuln.name[:60] + "..." if len(vuln.name) > 60 else vuln.name

            md_content += f"| {idx} | {cve_id} | {name} | {vuln.severity or '未知'} | {vuln.date} | {vuln.source} | {ref_str} |\n"

        md_content += "\n\n**注：** 表格中参考链接仅显示前3个，完整信息请查看各数据源详情部分\n\n---\n\n"

        # 保留各来源详细信息部分
        for source_name, vuln_list in vulns.items():
            md_content += f"## {source_name} 详细信息\n\n"
            if not vuln_list:
                md_content += "暂无漏洞信息\n\n"
                continue

            sorted_vulns = sorted(vuln_list, key=lambda x: getattr(x, 'severity', 'medium') or 'medium', reverse=True)

            for idx, vuln in enumerate(sorted_vulns, 1):
                md_content += format_markdown(vuln, idx)
                md_content += "\n---\n"

        return md_content

    def save_report(self, content, report_date=None):
        if not report_date:
            report_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        """保存Markdown报告到文件"""
        if not report_date:
            report_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"vulnerability_report_{report_date}.md"
        file_path = os.path.join(self.output_dir, filename)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"漏洞报告已保存至: {file_path}")
        return file_path

    def run(self):
        """执行完整的爬取和报告生成流程"""
        logger.info("===== 开始漏洞信息爬取流程 ====")
        vulns = self.fetch_all_vulns()
        if not vulns:
            logger.error("未获取到任何漏洞信息，无法生成报告")
            return None

        logger.info("开始生成Markdown报告")
        report_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_content = self.generate_markdown_report(vulns, report_date=report_date)
        report_path = self.save_report(report_content, report_date=report_date)

        logger.info("===== 漏洞信息爬取流程完成 ====")
        return report_path

if __name__ == "__main__":
    scraper = VulnScraper()
    scraper.run()
