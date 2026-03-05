import os
import re
import markdown
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QLabel, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QSplitter, QTextEdit,
                               QFileDialog, QMessageBox, QComboBox, QLineEdit,
                               QGroupBox, QCheckBox, QFrame, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QTextDocument, QFont, QColor, QPalette
from datetime import datetime
import glob

# 现代科技感配色方案
COLORS = {
    "bg_primary": "#0f172a",      # 深蓝黑背景（主背景）
    "bg_secondary": "#1e293b",    # 次级背景（输入框等）
    "bg_card": "#334155",         # 卡片背景（分组框）
    "accent_primary": "#06b6d4",  # 科技蓝（主要按钮、高亮）
    "accent_secondary": "#8b5cf6", # 紫色（次要按钮）
    "accent_success": "#10b981",  # 成功绿（搜索按钮）
    "accent_warning": "#f59e0b",  # 警告橙（高风险）
    "accent_danger": "#ef4444",   # 危险红（严重）
    "text_primary": "#ffffff",    # 主文本（白色）
    "text_secondary": "#ffffff",  # 次级文本（白色）
    "border": "#475569",          # 边框（深灰）
    "table_header": "#1e293b",    # 表头背景
    "table_alternate": "#1e293b",  # 表格交替行
    "table_selected": "#06b6d4",    # 表格选中行
}


class VulnerabilityReportViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_report = None
        self.current_vulnerabilities = []
        self.init_ui()
        self.load_reports()
    
    def init_ui(self):
        self.setWindowTitle("🛡️ 漏洞报告查看器 · 科技版")
        self.setGeometry(100, 100, 1400, 800)
        
        # 应用现代化样式表
        self.apply_modern_stylesheet()
        
        # 主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 主布局
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_widget.setLayout(main_layout)
        
        # 顶部控制区 - 分为两行
        # 第一行：路径选择和报告选择
        top_layout = QVBoxLayout()
        top_layout.setSpacing(12)
        
        # 路径选择区域
        path_layout = QHBoxLayout()
        path_layout.setSpacing(12)
        path_layout.setContentsMargins(0, 0, 0, 0)
        
        path_label = QLabel("📁 报告路径:")
        path_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px; min-width: 80px;")
        
        self.path_input = QLineEdit()
        self.path_input.setText(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerability_reports"))
        self.path_input.setStyleSheet(f"""
            background-color: {COLORS['bg_secondary']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 12px;
            min-height: 36px;
            border-left: 3px solid {COLORS['accent_primary']};
        """)
        
        browse_btn = self.create_button("📂 浏览", "secondary")
        browse_btn.clicked.connect(self.browse_report_path)
        
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_input, 1)
        path_layout.addWidget(browse_btn)
        
        # 第二行：报告选择和控制按钮
        control_layout = QHBoxLayout()
        control_layout.setSpacing(12)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        # 报告选择
        report_label = QLabel("📊 选择报告:")
        report_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px; min-width: 80px;")
        self.report_combo = self.create_combo_box()
        self.report_combo.setMinimumWidth(300)
        self.report_combo.currentIndexChanged.connect(self.on_report_changed)
        
        # 搜索框
        search_label = QLabel("🔍 搜索:")
        search_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px; min-width: 60px;")
        self.search_input = self.create_line_edit("输入 CVE ID 或漏洞名称...")
        self.search_input.setMinimumWidth(200)
        self.search_input.textChanged.connect(self.on_search_changed)
        
        # 严重程度筛选
        severity_label = QLabel("⚠️ 严重程度:")
        severity_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px; min-width: 90px;")
        self.severity_combo = self.create_combo_box()
        self.severity_combo.addItems(["全部", "极危", "高危", "中危", "低危", "高风险", "未知"])
        self.severity_combo.setMinimumWidth(100)
        self.severity_combo.currentIndexChanged.connect(self.on_filter_changed)
        
        # 来源筛选
        source_label = QLabel("🌐 来源:")
        source_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px; min-width: 60px;")
        self.source_combo = self.create_combo_box()
        self.source_combo.addItems(["全部"])
        self.source_combo.setMinimumWidth(100)
        self.source_combo.currentIndexChanged.connect(self.on_filter_changed)
        
        # 按钮容器
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        
        # 刷新按钮
        refresh_btn = self.create_button("🔄 刷新", "secondary")
        refresh_btn.clicked.connect(self.load_reports)
        
        # 导出按钮
        export_btn = self.create_button("📤 导出", "primary")
        export_btn.clicked.connect(self.export_report)
        
        button_layout.addWidget(refresh_btn)
        button_layout.addWidget(export_btn)
        
        control_layout.addWidget(report_label)
        control_layout.addWidget(self.report_combo)
        control_layout.addWidget(search_label)
        control_layout.addWidget(self.search_input)
        control_layout.addWidget(severity_label)
        control_layout.addWidget(self.severity_combo)
        control_layout.addWidget(source_label)
        control_layout.addWidget(self.source_combo)
        control_layout.addLayout(button_layout)
        control_layout.addStretch()
        
        top_layout.addLayout(path_layout)
        top_layout.addLayout(control_layout)
        
        main_layout.addLayout(top_layout)
        
        # 统计信息区域
        self.stats_label = QLabel("📈 统计信息: 加载中...")
        self.stats_label.setStyleSheet(f"""
            background: linear-gradient(135deg, {COLORS['bg_card']}, #1e293b);
            color: #ffffff;
            padding: 20px 25px;
            border-radius: 12px;
            border: 1px solid rgba(6, 182, 212, 0.3);
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 10px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.2);
            border-left: 4px solid {COLORS['accent_primary']};
            font-family: 'Segoe UI', 'Microsoft YaHei', 'PingFang SC', sans-serif;
            letter-spacing: 0.5px;
        """)
        # 设置标签居中对齐
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.stats_label)
        
        # 分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(3)
        
        # 左侧：漏洞列表
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(0)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_widget.setLayout(left_layout)
        
        # 漏洞表格
        self.vuln_table = self.create_table_widget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "CVE ID", "漏洞名称", "严重程度", "发布日期", "来源"])
        
        # 设置列宽调整模式
        header = self.vuln_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # ID列固定宽度
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # CVE ID列自动调整
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # 漏洞名称列拉伸
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)  # 严重程度列固定宽度
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)  # 发布日期列固定宽度
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)  # 来源列固定宽度
        
        # 设置固定列宽
        self.vuln_table.setColumnWidth(0, 60)  # ID列
        self.vuln_table.setColumnWidth(3, 80)  # 严重程度列
        self.vuln_table.setColumnWidth(4, 100)  # 发布日期列
        self.vuln_table.setColumnWidth(5, 100)  # 来源列
        
        # 设置行高
        self.vuln_table.verticalHeader().setDefaultSectionSize(30)  # 增加行高
        # 隐藏垂直表头（行号列）
        self.vuln_table.verticalHeader().setVisible(False)
        
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vuln_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.vuln_table.itemDoubleClicked.connect(self.on_vuln_double_clicked)
        self.vuln_table.itemClicked.connect(self.on_vuln_selected)
        left_layout.addWidget(self.vuln_table)
        
        # 右侧：详细信息
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setSpacing(0)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_widget.setLayout(right_layout)
        
        # 详情标题
        detail_title = QLabel("📖 漏洞详细信息")
        detail_title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        detail_title.setStyleSheet(f"""
            color: #ffffff;
            font-weight: bold;
            padding: 18px 20px;
            border-bottom: 2px solid {COLORS['border']};
            background: linear-gradient(135deg, {COLORS['bg_card']}, #1e293b);
            border-left: 8px solid {COLORS['accent_primary']};
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        """)
        detail_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(detail_title)
        
        # 详情文本框容器（用于居中）
        detail_container = QWidget()
        detail_container_layout = QVBoxLayout()
        detail_container_layout.setContentsMargins(30, 20, 30, 20)
        detail_container_layout.setSpacing(15)
        detail_container.setLayout(detail_container_layout)
        
        # 详情文本框
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMarkdown("")
        self.detail_text.setStyleSheet(f"""
            background-color: {COLORS['bg_secondary']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
            border-radius: 12px;
            padding: 25px;
            font-size: 18px;
            font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
            line-height: 1.8;
        """)
        detail_container_layout.addWidget(self.detail_text, 1)  # 添加拉伸因子
        right_layout.addWidget(detail_container, 1)  # 添加拉伸因子
        
        # 添加到分割器
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 5)  # 左侧列表区域
        splitter.setStretchFactor(1, 3)  # 右侧详情区域
        
        main_layout.addWidget(splitter, 1)
        
    def browse_report_path(self):
        """浏览报告路径"""
        default_path = self.path_input.text() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerability_reports")
        
        directory = QFileDialog.getExistingDirectory(
            self, "选择报告目录", 
            default_path,
            QFileDialog.Option.ShowDirsOnly
        )
        
        if directory:
            self.path_input.setText(directory)
            self.load_reports()
    
    def apply_modern_stylesheet(self):
        """应用现代科技感样式表"""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS["bg_primary"]};
                color: #ffffff;
                font-size: 12px;
            }}
            QWidget {{
                background-color: {COLORS["bg_primary"]};
                color: #ffffff;
                font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
                font-size: 12px;
            }}
            QComboBox {{
                background-color: {COLORS["bg_secondary"]};
                color: #ffffff;
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 8px 12px;
                selection-background-color: {COLORS["accent_primary"]};
                selection-color: {COLORS["bg_primary"]};
                font-size: 12px;
                min-height: 30px;
            }}
            QComboBox:focus {{
                border-color: {COLORS["accent_primary"]};
                background-color: {COLORS["bg_card"]};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS["bg_secondary"]};
                color: #ffffff;
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                selection-background-color: {COLORS["accent_primary"]};
                selection-color: {COLORS["bg_primary"]};
                font-size: 12px;
            }}
            QLineEdit {{
                background-color: {COLORS["bg_secondary"]};
                color: #ffffff;
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 8px 12px;
                selection-background-color: {COLORS["accent_primary"]};
                selection-color: {COLORS["bg_primary"]};
                font-size: 12px;
                min-height: 30px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS["accent_primary"]};
                background-color: {COLORS["bg_card"]};
            }}
            QTableWidget {{
                background-color: {COLORS["bg_secondary"]};
                color: #ffffff;
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                gridline-color: {COLORS["border"]};
                font-size: 12px;
            }}
            QTableWidget::item {{
                padding: 10px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS["table_selected"]};
                color: {COLORS["bg_primary"]};
                font-weight: bold;
            }}
            QHeaderView::section {{
                background-color: {COLORS["table_header"]};
                color: {COLORS["accent_primary"]};
                padding: 12px;
                border: none;
                border-bottom: 2px solid {COLORS["accent_primary"]};
                font-weight: bold;
                font-size: 12px;
            }}
            QSplitter::handle {{
                background-color: {COLORS["border"]};
                width: 3px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS["accent_primary"]};
            }}
            QScrollBar:vertical {{
                background-color: {COLORS["bg_secondary"]};
                width: 14px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS["border"]};
                border-radius: 6px;
                min-height: 25px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {COLORS["accent_primary"]};
            }}
            QScrollBar:horizontal {{
                background-color: {COLORS["bg_secondary"]};
                height: 14px;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {COLORS["border"]};
                border-radius: 6px;
                min-width: 25px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: {COLORS["accent_primary"]};
            }}
            QTextEdit {{
                background-color: {COLORS["bg_card"]};
                color: #ffffff;
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                padding: 18px;
                font-size: 14px;
                font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
                line-height: 1.6;
            }}
            QTextEdit:focus {{
                border-color: {COLORS["accent_primary"]};
            }}
            QLabel {{
                font-size: 12px;
                color: #ffffff;
            }}
        """)
    
    def create_button(self, text, button_type="primary"):
        """创建现代化按钮"""
        btn = QPushButton(text)
        
        if button_type == "primary":
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS["accent_primary"]};
                    color: {COLORS["bg_primary"]};
                    border: none;
                    border-radius: 8px;
                    padding: 10px 18px;
                    font-weight: bold;
                    font-size: 12px;
                    min-width: 90px;
                    min-height: 36px;
                    transition: all 0.2s ease;
                }}
                QPushButton:hover {{
                    background-color: #0891b2;
                    transform: translateY(-1px);
                }}
                QPushButton:pressed {{
                    background-color: #0891b2;
                    transform: translateY(0);
                }}
            """)
        elif button_type == "secondary":
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS["accent_secondary"]};
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 10px 18px;
                    font-weight: bold;
                    font-size: 12px;
                    min-width: 90px;
                    min-height: 36px;
                    transition: all 0.2s ease;
                }}
                QPushButton:hover {{
                    background-color: #7c3aed;
                    transform: translateY(-1px);
                }}
                QPushButton:pressed {{
                    background-color: #7c3aed;
                    transform: translateY(0);
                }}
            """)
        
        return btn
    
    def create_line_edit(self, placeholder_text):
        """创建现代化输入框"""
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder_text)
        return edit
    
    def create_combo_box(self):
        """创建现代化下拉框"""
        combo = QComboBox()
        return combo
    
    def create_table_widget(self):
        """创建现代化表格"""
        table = QTableWidget()
        table.setAlternatingRowColors(True)
        table.setStyleSheet(f"""
            QTableWidget {{
                alternate-background-color: {COLORS["table_alternate"]};
            }}
        """)
        return table
    
    def load_reports(self):
        """加载所有可用的报告文件"""
        reports_dir = self.path_input.text()
        if not os.path.exists(reports_dir):
            QMessageBox.warning(self, "错误", f"报告目录不存在: {reports_dir}")
            return
        
        # 查找所有 md 文件
        pattern = os.path.join(reports_dir, "vulnerability_report_*.md")
        report_files = glob.glob(pattern)
        
        if not report_files:
            QMessageBox.warning(self, "警告", "没有找到任何报告文件")
            return
        
        # 按文件名排序（最新的在前）
        report_files.sort(reverse=True)
        
        # 保存当前选择
        current_index = self.report_combo.currentIndex()
        current_text = self.report_combo.currentText()
        
        # 清空并重新填充
        self.report_combo.clear()
        for report_file in report_files:
            filename = os.path.basename(report_file)
            # 提取日期时间
            match = re.search(r'vulnerability_report_(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})', filename)
            if match:
                date_str = match.group(1)
                time_str = match.group(2)
                display_text = f"{date_str} {time_str}"
            else:
                display_text = filename
            self.report_combo.addItem(display_text, report_file)
        
        # 恢复选择
        if current_text:
            index = self.report_combo.findText(current_text)
            if index >= 0:
                self.report_combo.setCurrentIndex(index)
        
        # 加载第一个报告
        if self.report_combo.count() > 0:
            self.load_report(0)
    
    def load_report(self, index):
        """加载指定索引的报告"""
        if index < 0 or index >= self.report_combo.count():
            return
        
        report_file = self.report_combo.itemData(index)
        self.current_report = report_file
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 解析报告
            self.parse_report(content)
            
            # 更新来源筛选器
            self.update_source_filter()
            
            # 应用筛选
            self.apply_filters()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载报告失败: {str(e)}")
    
    def parse_report(self, content):
        """解析报告内容"""
        self.current_vulnerabilities = []
        
        # 提取生成时间
        time_match = re.search(r'\*\*生成时间\*\*:\s*(.+)', content)
        self.generation_time = time_match.group(1).strip() if time_match else "未知"
        
        # 提取表格数据
        # 改进表格解析正则表达式，支持更多格式变体
        table_pattern = r'\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|'
        matches = re.findall(table_pattern, content)
        
        for match in matches:
            vuln = {
                'id': match[0].strip(),
                'cve_id': match[1].strip(),
                'name': match[2].strip(),
                'severity': match[3].strip(),
                'date': match[4].strip(),
                'source': match[5].strip(),
                'reference': match[6].strip() if match[6].strip() != '-' else ''
            }
            self.current_vulnerabilities.append(vuln)
        
        # 提取详细信息
        self.extract_details(content)
    
    def extract_details(self, content):
        """提取每个漏洞的详细信息"""
        # 按数据源分割内容
        sections = re.split(r'##\s+(\w+)\s+详细信息', content)
        
        for i in range(1, len(sections), 2):
            if i + 1 < len(sections):
                source = sections[i].strip()
                detail_content = sections[i + 1].strip()
                
                # 提取每个漏洞的详细信息
                # 改进正则表达式，支持更多格式变体
                vuln_pattern = r'###\s*(\d+)\.\s*(.+?)(?:\n|$)(.*?)(?=###|$)'
                vuln_matches = re.findall(vuln_pattern, detail_content, re.DOTALL)
                
                for vuln_match in vuln_matches:
                    vuln_id = vuln_match[0].strip()
                    vuln_name = vuln_match[1].strip()
                    vuln_detail = vuln_match[2].strip()
                    
                    # 查找对应的漏洞并添加详细信息
                    for vuln in self.current_vulnerabilities:
                        if vuln['id'] == vuln_id:
                            vuln['detail'] = vuln_detail
                            # 添加来源信息
                            if not vuln.get('source'):
                                vuln['source'] = source
                            break
    
    def update_source_filter(self):
        """更新来源筛选器"""
        sources = set()
        for vuln in self.current_vulnerabilities:
            sources.add(vuln['source'])
        
        # 保存当前选择
        current_text = self.source_combo.currentText()
        
        self.source_combo.clear()
        self.source_combo.addItem("全部")
        for source in sorted(sources):
            self.source_combo.addItem(source)
        
        # 恢复选择
        if current_text:
            index = self.source_combo.findText(current_text)
            if index >= 0:
                self.source_combo.setCurrentIndex(index)
    
    def apply_filters(self):
        """应用筛选条件"""
        search_text = self.search_input.text().lower()
        severity_filter = self.severity_combo.currentText()
        source_filter = self.source_combo.currentText()
        
        filtered_vulns = []
        for vuln in self.current_vulnerabilities:
            # 搜索筛选
            if search_text:
                search_match = False
                # 搜索多个字段
                for field in ['cve_id', 'name', 'source']:
                    if search_text in str(vuln.get(field, '')).lower():
                        search_match = True
                        break
                if not search_match:
                    continue
            
            # 严重程度筛选
            if severity_filter != "全部" and vuln['severity'] != severity_filter:
                continue
            
            # 来源筛选
            if source_filter != "全部" and vuln['source'] != source_filter:
                continue
            
            filtered_vulns.append(vuln)
        
        # 更新表格
        self.update_table(filtered_vulns)
        
        # 更新统计信息
        self.update_stats(filtered_vulns)
    
    def update_table(self, vulnerabilities):
        """更新漏洞表格"""
        self.vuln_table.setRowCount(len(vulnerabilities))
        
        for row, vuln in enumerate(vulnerabilities):
            self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln['id']))
            self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln['cve_id']))
            self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln['name']))
            self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln['severity']))
            self.vuln_table.setItem(row, 4, QTableWidgetItem(vuln['date']))
            self.vuln_table.setItem(row, 5, QTableWidgetItem(vuln['source']))
            
            # 根据严重程度设置颜色
            severity = vuln['severity']
            bg_color = self.get_severity_color(severity)
            for col in range(6):
                item = self.vuln_table.item(row, col)
                if item:
                    item.setBackground(bg_color)
                    
                    # 设置文字颜色
                    if severity == "极危" or severity == "高危" or severity == "高风险":
                        item.setForeground(QColor("#ffffff"))
                    else:
                        item.setForeground(QColor(COLORS["text_primary"]))
    
    def get_severity_color(self, severity):
        """根据严重程度获取背景颜色"""
        color_map = {
            "极危": QColor(COLORS["accent_danger"]),
            "高危": QColor(COLORS["accent_warning"]),
            "高风险": QColor(COLORS["accent_warning"]),
            "中危": QColor(COLORS["accent_success"]),
            "低危": QColor(COLORS["accent_secondary"]),
            "未知": QColor(COLORS["border"]),
        }
        return color_map.get(severity, QColor(COLORS["border"]))
    
    def update_stats(self, vulnerabilities):
        """更新统计信息"""
        total = len(vulnerabilities)
        
        # 按严重程度统计
        severity_count = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        # 按来源统计
        source_count = {}
        for vuln in vulnerabilities:
            source = vuln['source']
            source_count[source] = source_count.get(source, 0) + 1
        
        # 构建统计信息
        stats_text = f"总计: {total} 个漏洞 | 生成时间: {self.generation_time} | "
        stats_text += "严重程度: " + ", ".join([f"{k}: {v}" for k, v in sorted(severity_count.items())])
        self.stats_label.setText(stats_text)
    
    def on_report_changed(self, index):
        """报告选择改变事件"""
        self.load_report(index)
    
    def on_search_changed(self, text):
        """搜索文本改变事件"""
        self.apply_filters()
    
    def on_filter_changed(self, index):
        """筛选条件改变事件"""
        self.apply_filters()
    
    def on_vuln_double_clicked(self, item):
        """漏洞双击事件"""
        row = item.row()
        vuln_id = self.vuln_table.item(row, 0).text()
        
        # 查找漏洞详细信息
        vuln = None
        for v in self.current_vulnerabilities:
            if v['id'] == vuln_id:
                vuln = v
                break
        
        if vuln:
            self.show_vuln_detail(vuln)
    
    def on_vuln_selected(self, item):
        """漏洞选择事件"""
        # 当选择单个漏洞时，自动显示详细信息
        selected_items = self.vuln_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            vuln_id = self.vuln_table.item(row, 0).text()
            
            # 查找漏洞详细信息
            vuln = None
            for v in self.current_vulnerabilities:
                if v['id'] == vuln_id:
                    vuln = v
                    break
            
            if vuln:
                self.show_vuln_detail(vuln)
    
    def show_vuln_detail(self, vuln):
        """显示漏洞详细信息"""
        # 根据严重程度获取颜色
        severity = vuln['severity']
        severity_color = self.get_severity_color(severity)
        
        # 构建更美观的Markdown内容
        detail_text = f"""# 🛡️ {vuln['name']}

---

### 📊 漏洞概览

| **🆔 ID** | **🔖 CVE编号** | **⚡ 严重程度** | **📅 发布日期** | **🌐 来源** |
|:---:|:---:|:---:|:---:|:---:|
| {vuln['id']} | {vuln['cve_id']} | {severity} | {vuln['date']} | {vuln['source']} |

---

### 📝 漏洞描述

"""
        
        # 添加漏洞描述
        if vuln.get('detail'):
            detail_text += vuln['detail']
        else:
            detail_text += "暂无详细信息"
        
        # 添加参考链接
        if vuln.get('reference'):
            detail_text += f"""
---

### 🔗 参考链接

{vuln['reference']}
"""
        
        # 添加分隔线
        detail_text += f"""
---

*📋 数据来源: 漏洞情报报告 | 生成时间: {self.generation_time}*"""
        
        # 调整文本编辑器字体大小
        self.detail_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 18px;
                font-size: 14px;
                font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
                line-height: 1.6;
            }}
            QTextEdit:focus {{
                border-color: {COLORS['accent_primary']};
            }}
        """)
        
        self.detail_text.setMarkdown(detail_text)
    
    def export_report(self):
        """导出当前报告"""
        if not self.current_report:
            QMessageBox.warning(self, "警告", "没有选择报告")
            return
        
        # 选择保存位置
        filename, _ = QFileDialog.getSaveFileName(
            self, "📤 导出报告", 
            os.path.basename(self.current_report).replace('.md', '_exported.md'),
            "Markdown 文件 (*.md);;CSV 文件 (*.csv);;所有文件 (*.*)"
        )
        
        if filename:
            try:
                if filename.endswith('.csv'):
                    # 导出为CSV格式
                    self.export_to_csv(filename)
                else:
                    # 导出为Markdown格式
                    # 读取原始报告
                    with open(self.current_report, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 写入新文件
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                
                # 显示成功消息
                success_msg = QMessageBox(self)
                success_msg.setWindowTitle("✅ 导出成功")
                success_msg.setText(f"报告已成功导出到:\n\n{filename}")
                success_msg.setIcon(QMessageBox.Icon.Information)
                success_msg.setStyleSheet(f"""
                    QMessageBox {{
                        background-color: {COLORS['bg_secondary']};
                        color: {COLORS['text_primary']};
                    }}
                    QPushButton {{
                        background-color: {COLORS['accent_primary']};
                        color: {COLORS['bg_primary']};
                        border: none;
                        border-radius: 6px;
                        padding: 6px 12px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: #0891b2;
                    }}
                """)
                success_msg.exec()
            except Exception as e:
                # 显示错误消息
                error_msg = QMessageBox(self)
                error_msg.setWindowTitle("❌ 导出失败")
                error_msg.setText(f"导出报告时发生错误:\n\n{str(e)}")
                error_msg.setIcon(QMessageBox.Icon.Critical)
                error_msg.setStyleSheet(f"""
                    QMessageBox {{
                        background-color: {COLORS['bg_secondary']};
                        color: {COLORS['text_primary']};
                    }}
                    QPushButton {{
                        background-color: {COLORS['accent_danger']};
                        color: white;
                        border: none;
                        border-radius: 6px;
                        padding: 6px 12px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: #dc2626;
                    }}
                """)
                error_msg.exec()
    
    def export_to_csv(self, filename):
        """导出为CSV格式"""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['ID', 'CVE ID', '漏洞名称', '严重程度', '发布日期', '来源', '参考链接']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in self.current_vulnerabilities:
                writer.writerow({
                    'ID': vuln['id'],
                    'CVE ID': vuln['cve_id'],
                    '漏洞名称': vuln['name'],
                    '严重程度': vuln['severity'],
                    '发布日期': vuln['date'],
                    '来源': vuln['source'],
                    '参考链接': vuln.get('reference', '')
                })


def main():
    app = QApplication([])
    viewer = VulnerabilityReportViewer()
    viewer.show()
    app.exec()


if __name__ == "__main__":
    main()
