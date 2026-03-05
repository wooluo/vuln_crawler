import sys
import datetime as dt
import threading
import json
import csv
from typing import Optional, List

import requests
from PyQt6.QtCore import (
    Qt,
    QTimer,
    QMutex,
    pyqtSignal,
    QPropertyAnimation,
    QEasingCurve,
    QParallelAnimationGroup,
)
from PyQt6.QtGui import (
    QColor,
    QTextCursor,
    QFont,
    QIcon,
    QPalette,
    QBrush,
    QLinearGradient,
    QFontMetrics,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QPushButton,
    QLineEdit,
    QDateEdit,
    QMessageBox,
    QComboBox,
    QMenu,
    QTextBrowser,
    QFrame,
    QGroupBox,
    QStatusBar,
    QProgressBar,
    QSpacerItem,
    QSizePolicy,
    QHeaderView,
    QDialog,
)

from models import VulnItem
from utils import fetch_all, set_proxy, _session  # noqa: F401 – _session might be unused directly here
import changtin
import oscs
import qianxin
import threatbook
import cisa
from poc_fetcher import fetch_poc_urls, set_github_token
from config_io import load_cfg, save_cfg
from html import escape
from vuln_search import search_vulns

# ---------------------------------------------------------------------------
# 常量配置
# ---------------------------------------------------------------------------
DATE_FETCHERS = [
    changtin.fetch_changtin,
    oscs.fetch_oscs,
    qianxin.fetch_qianxin,
    threatbook.fetch_threatbook,
    cisa.fetch_cisa,
]
PAGE_SIZE = 30

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
    "text_primary": "#f8fafc",    # 主文本（白色）
    "text_secondary": "#cbd5e1",  # 次级文本（浅灰）
    "border": "#475569",          # 边框（深灰）
}

# 严重程度配色
SEV_COLOR = {
    "严重": QColor("#bd93f9"),    # 紫
    "极危": QColor("#ff5555"),    # 红
    "高危": QColor("#ffb86c"),    # 橙
    "高风险": QColor("#50fa7b"),  # 绿
    "中危": QColor("#f1fa8c"),    # 黄
}


# ---------------------------------------------------------------------------
# 主窗口（现代化重构版）
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    data_ready = pyqtSignal(list)
    proxy_test_done = pyqtSignal(str)
    add_html = pyqtSignal(str)
    search_finished = pyqtSignal(list)
    sources_test_done = pyqtSignal(str)

    # ---------------------------------------------------------------------
    # 初始化
    # ---------------------------------------------------------------------
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("🛡️ 高价值漏洞采集 & 推送系统 · 科技版")
        self.resize(1400, 950)

        # 设置全局字体
        font = QFont("Segoe UI", 11)
        QApplication.setFont(font)

        # 应用现代化样式表
        self.apply_modern_stylesheet()

        # 设置窗口居中
        self.center_window()

        container = QWidget(self)
        self.setCentralWidget(container)
        root = QVBoxLayout(container)
        root.setSpacing(12)
        root.setContentsMargins(15, 15, 15, 15)

        # --------------------------------------------------------------
        # 顶栏 - 分组框：数据范围与搜索
        # --------------------------------------------------------------
        group_data = self.create_group_box("📊 数据范围与搜索")
        layout_data = QHBoxLayout(group_data)
        layout_data.setSpacing(15)
        layout_data.setContentsMargins(15,15,15,15)

        # 整体居中布局
        center_layout = QHBoxLayout()
        center_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 日期范围
        date_group = QHBoxLayout()
        date_group.setSpacing(10)
        
        # 日期选择区域
        date_range_group = QHBoxLayout()
        date_range_group.setSpacing(10)
        
        # 起始日期
        date_range_group.addWidget(self.create_label("起始日期:"))
        self.date_from = self.create_date_edit()
        self.date_from.setDate(dt.date.today() - dt.timedelta(days=2))
        self.date_from.setFixedWidth(160)
        date_range_group.addWidget(self.date_from)
        
        # 结束日期
        date_range_group.addWidget(self.create_label("结束日期:"))
        self.date_to = self.create_date_edit()
        self.date_to.setDate(dt.date.today())
        self.date_to.setFixedWidth(160)
        date_range_group.addWidget(self.date_to)
        
        # 快捷日期按钮
        quick_dates_group = QHBoxLayout()
        quick_dates_group.setSpacing(5)
        
        today_btn = self.create_button("今天", "secondary")
        today_btn.setFixedWidth(60)
        today_btn.clicked.connect(lambda: self.set_date_range(dt.date.today(), dt.date.today()))
        quick_dates_group.addWidget(today_btn)
        
        yesterday_btn = self.create_button("昨天", "secondary")
        yesterday_btn.setFixedWidth(60)
        yesterday_btn.clicked.connect(lambda: self.set_date_range(dt.date.today() - dt.timedelta(days=1), dt.date.today() - dt.timedelta(days=1)))
        quick_dates_group.addWidget(yesterday_btn)
        
        last7_btn = self.create_button("近7天", "secondary")
        last7_btn.setFixedWidth(60)
        last7_btn.clicked.connect(lambda: self.set_date_range(dt.date.today() - dt.timedelta(days=6), dt.date.today()))
        quick_dates_group.addWidget(last7_btn)
        
        last30_btn = self.create_button("近30天", "secondary")
        last30_btn.setFixedWidth(60)
        last30_btn.clicked.connect(lambda: self.set_date_range(dt.date.today() - dt.timedelta(days=29), dt.date.today()))
        quick_dates_group.addWidget(last30_btn)
        
        # 添加到主日期组
        date_group.addLayout(date_range_group)
        date_group.addSpacing(15)
        date_group.addLayout(quick_dates_group)

        button_group = QHBoxLayout()
        button_group.setSpacing(10)
        self.refresh_btn = self.create_button("🔄 刷新爬取", "primary")
        self.refresh_btn.clicked.connect(self.load_data)
        self.refresh_btn.setFixedWidth(120)
        button_group.addWidget(self.refresh_btn)

        self.reset_btn = self.create_button("⟲ 重置", "secondary")
        self.reset_btn.clicked.connect(self.reset_view)
        self.reset_btn.setFixedWidth(100)
        button_group.addWidget(self.reset_btn)

        search_group = QHBoxLayout()
        search_group.setSpacing(10)
        search_group.addWidget(self.create_label("🔍 漏洞搜索:"))
        self.search_edit = self.create_line_edit("输入 CVE 编号或漏洞名称", 300)
        self.search_edit.returnPressed.connect(self.search_vulns_gui)
        search_group.addWidget(self.search_edit)

        self.search_btn = self.create_button("🔎 搜索", "accent")
        self.search_btn.clicked.connect(self.search_vulns_gui)
        self.search_btn.setFixedWidth(80)
        search_group.addWidget(self.search_btn)

        center_layout.addLayout(date_group)
        center_layout.addSpacing(20)
        center_layout.addLayout(button_group)
        center_layout.addSpacing(20)
        center_layout.addLayout(search_group)

        layout_data.addLayout(center_layout)
        root.addWidget(group_data)

        # --------------------------------------------------------------
        # 顶栏 - 分组框：认证与代理设置
        # --------------------------------------------------------------
        group_auth_proxy = self.create_group_box("⚙️ 认证与代理设置")
        layout_auth_proxy = QHBoxLayout(group_auth_proxy)
        layout_auth_proxy.setSpacing(15)
        layout_auth_proxy.setContentsMargins(15, 15, 15, 15)

        # 认证部分
        auth_group = QHBoxLayout()
        auth_group.setSpacing(10)
        auth_group.addWidget(self.create_label("认证目标源:"))
        self.src_combo = self.create_combo_box(["ThreatBook", "GitHub"])
        self.src_combo.currentIndexChanged.connect(self._on_src_change)
        self.src_combo.setFixedWidth(120)
        auth_group.addWidget(self.src_combo)

        self.auth_edit = self.create_line_edit("粘贴整串 Cookie", 300)
        auth_group.addWidget(self.auth_edit)

        self.auth_btn = self.create_button("⚡ 应用认证", "primary")
        self.auth_btn.clicked.connect(self.apply_auth)
        self.auth_btn.setFixedWidth(100)
        auth_group.addWidget(self.auth_btn)

        # 代理部分
        proxy_group = QHBoxLayout()
        proxy_group.setSpacing(10)
        proxy_group.addWidget(self.create_label("HTTP 代理:"))
        self.http_edit = self.create_line_edit("127.0.0.1:7890", 150)
        proxy_group.addWidget(self.http_edit)

        proxy_group.addWidget(self.create_label("HTTPS 代理:"))
        self.https_edit = self.create_line_edit("127.0.0.1:7890", 150)
        proxy_group.addWidget(self.https_edit)

        self.proxy_btn = self.create_button("🌐 应用代理", "secondary")
        self.proxy_btn.clicked.connect(self.apply_proxy)
        self.proxy_btn.setFixedWidth(100)
        proxy_group.addWidget(self.proxy_btn)

        self.test_btn = self.create_button("🧪 测试代理", "accent")
        self.test_btn.clicked.connect(self.test_proxy)
        self.test_btn.setFixedWidth(100)
        proxy_group.addWidget(self.test_btn)

        self.test_sources_btn = self.create_button("🔍 测试数据源", "primary")
        self.test_sources_btn.clicked.connect(self.test_data_sources)
        self.test_sources_btn.setFixedWidth(120)
        proxy_group.addWidget(self.test_sources_btn)

        # 居中布局
        auth_center = QHBoxLayout()
        auth_center.setAlignment(Qt.AlignmentFlag.AlignCenter)
        auth_center.addLayout(auth_group)
        auth_center.addSpacing(20)
        auth_center.addLayout(proxy_group)

        layout_auth_proxy.addLayout(auth_center)
        root.addWidget(group_auth_proxy)

        # 分隔线
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setObjectName("separator")
        root.addWidget(separator)

        # --------------------------------------------------------------
        # 中部：表格 + 详情
        # --------------------------------------------------------------
        mid = QHBoxLayout()
        mid.setSpacing(12)

        # 表格容器
        table_group = self.create_group_box("📋 漏洞列表")
        table_layout = QVBoxLayout(table_group)
        table_layout.setContentsMargins(5, 5, 5, 5)

        self.table = self.create_table_widget()
        table_layout.addWidget(self.table)

        mid.addWidget(table_group, 3)

        # 详情容器
        detail_group = self.create_group_box("📖 漏洞详情")
        detail_layout = QVBoxLayout(detail_group)
        detail_layout.setContentsMargins(6, 6, 6, 6)

        self.detail_box = self.create_text_browser()
        detail_layout.addWidget(self.detail_box)

        mid.addWidget(detail_group, 5)

        root.addLayout(mid)

        # --------------------------------------------------------------
        # 分页导航
        # --------------------------------------------------------------
        nav = QHBoxLayout()
        nav.setContentsMargins(0, 15, 0, 15)
        nav.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav.setSpacing(15)

        # 首页按钮
        self.first_btn = self.create_button("⏮ 首页", "secondary")
        self.first_btn.clicked.connect(lambda: self.change_page(-self.page))
        self.first_btn.setEnabled(False)
        self.first_btn.setFixedWidth(80)
        nav.addWidget(self.first_btn)

        # 上一页按钮
        self.prev_btn = self.create_button("◀ 上一页", "secondary")
        self.prev_btn.clicked.connect(lambda: self.change_page(-1))
        self.prev_btn.setEnabled(False)
        self.prev_btn.setFixedWidth(100)
        nav.addWidget(self.prev_btn)

        # 页码显示
        self.page_label = QLabel("第 1 页，共 0 页")
        self.page_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 12px; font-weight: bold;")
        self.page_label.setFixedWidth(120)
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav.addWidget(self.page_label)

        # 下一页按钮
        self.next_btn = self.create_button("下一页 ▶", "secondary")
        self.next_btn.clicked.connect(lambda: self.change_page(1))
        self.next_btn.setEnabled(False)
        self.next_btn.setFixedWidth(100)
        nav.addWidget(self.next_btn)

        # 末页按钮
        self.last_btn = self.create_button("末页 ⏭", "secondary")
        self.last_btn.clicked.connect(self.go_to_last_page)
        self.last_btn.setEnabled(False)
        self.last_btn.setFixedWidth(80)
        nav.addWidget(self.last_btn)

        root.addLayout(nav)

        # --------------------------------------------------------------
        # 状态栏
        # --------------------------------------------------------------
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setObjectName("statusBar")

        self.status_label = QLabel("🟢 就绪 - 等待操作")
        self.status_label.setStyleSheet("color: #00ff9d; font-weight: bold;")
        self.status_bar.addWidget(self.status_label, 1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.count_label = QLabel("共 0 条漏洞")
        self.count_label.setStyleSheet(f"color: {COLORS['accent_primary']}; font-weight: 500;")
        self.status_bar.addPermanentWidget(self.count_label)
        
        # 初始化分页状态
        self.page = 0
        self.full_data = []
        self.update_table()

        # --------------------------------------------------------------
        # 运行时状态
        # --------------------------------------------------------------
        self.full_data: list[VulnItem] = []
        self.page = 0
        self._mtx = QMutex()
        self._click_token = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_data)

        # 关联信号
        self.data_ready.connect(self.on_data_ready)
        self.add_html.connect(self._append_html)
        self.proxy_test_done.connect(self._show_proxy_msg)
        self.search_finished.connect(self.handle_search_results)
        self.sources_test_done.connect(self._show_sources_msg)

        # ⚠️ 移除启动时自动加载数据
        # self.load_data()  # 已注释，改为手动触发

        # 读取保存的 GitHub Token
        cfg = load_cfg()
        if token := cfg.get("github_token"):
            set_github_token(token)
            self.auth_edit.setText(token)

        # 更新状态栏
        self.update_status('🟢 就绪 - 请点击"刷新爬取"按钮开始采集', 'success')

    # ------------------------------------------------------------------
    # UI 组件工厂方法
    # ------------------------------------------------------------------
    def apply_modern_stylesheet(self):
        """应用现代科技感样式表"""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS["bg_primary"]};
                color: {COLORS["text_primary"]};
                font-size: 11px;
            }}}}
            QWidget {{
                background-color: {COLORS["bg_primary"]};
                color: {COLORS["text_primary"]};
                font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
                font-size: 11px;
            }}
            QGroupBox {{
                background-color: {COLORS["bg_card"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 12px;
                margin-top: 20px;
                font-weight: bold;
                padding-top: 15px;
                font-size: 13px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 10px;
                color: {COLORS["accent_primary"]};
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton {{
                background-color: {COLORS["bg_secondary"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 80px;
                font-size: 11px;
                transition: all 0.2s ease;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }}
            QPushButton:hover {{
                background-color: {COLORS["bg_card"]};
                border-color: {COLORS["accent_primary"]};
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            }}
            QPushButton:pressed {{
                background-color: {COLORS["accent_primary"]};
                color: {COLORS["bg_primary"]};
                transform: translateY(0);
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
            }}
            QPushButton:disabled {{
                background-color: {COLORS["bg_secondary"]};
                color: {COLORS["text_secondary"]};
                border-color: {COLORS["border"]};
                transform: none;
            }}
            QPushButton#primary {{
                background-color: {COLORS["accent_primary"]};
                color: {COLORS["bg_primary"]};
                border: none;
            }}
            QPushButton#primary:hover {{
                background-color: #0891b2;
            }}
            QPushButton#secondary {{
                background-color: {COLORS["accent_secondary"]};
                color: white;
                border: none;
            }}
            QPushButton#secondary:hover {{
                background-color: #7c3aed;
            }}
            QPushButton#accent {{
                background-color: {COLORS["accent_success"]};
                color: {COLORS["bg_primary"]};
                border: none;
            }}
            QPushButton#accent:hover {{
                background-color: #059669;
            }}
            QLineEdit, QDateEdit, QComboBox {{
                background-color: {COLORS["bg_secondary"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: {COLORS["accent_primary"]};
                selection-color: {COLORS["bg_primary"]};
                font-size: 11px;
                transition: border-color 0.2s ease;
            }}
            QLineEdit:focus, QDateEdit:focus, QComboBox:focus {{
                border-color: {COLORS["accent_primary"]};
                background-color: {COLORS["bg_card"]};
            }}
            QDateEdit::down-arrow, QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid {COLORS["accent_primary"]};
                margin-right: 8px;
            }}
            QDateEdit:focus::drop-down, QComboBox:focus::drop-down {{
                background-color: {COLORS["bg_card"]};
            }}
            QComboBox QAbstractItemView {{
                background-color: {{COLORS["bg_secondary"]}};
                color: {{COLORS["text_primary"]}};
                border: 1px solid {{COLORS["border"]}};
                border-radius: 6px;
                selection-background-color: {{COLORS["accent_primary"]}};
                selection-color: {{COLORS["bg_primary"]}};
                font-size: 11px;
            }}
            QTableWidget {{
                background-color: {COLORS["bg_secondary"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                gridline-color: {COLORS["border"]};
                selection-background-color: rgba(6, 182, 212, 0.2);
                alternate-background-color: {COLORS["bg_card"]};
                box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
            }}
            QTableWidget::item {{
                padding: 8px;
                border: none;
                font-size: 11px;
                transition: background-color 0.2s ease;
            }}
            QTableWidget::item:selected {{
                background-color: rgba(6, 182, 212, 0.3);
                border: 1px solid {COLORS["accent_primary"]};
            }}
            QHeaderView::section {{
                background-color: {COLORS["bg_card"]};
                color: {COLORS["accent_primary"]};
                border: 1px solid {COLORS["border"]};
                padding: 10px;
                font-weight: bold;
                font-size: 11px;
            }}
            QTextBrowser {{
                background-color: {COLORS["bg_secondary"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                padding: 12px;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }}
            QTextBrowser a {{
                color: {COLORS["accent_primary"]};
                text-decoration: none;
            }}
            QTextBrowser a:hover {{
                color: {COLORS["accent_secondary"]};
                text-decoration: underline;
            }}
            QProgressBar {{
                background-color: {COLORS["bg_secondary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                text-align: center;
                color: {COLORS["accent_primary"]};
                font-size: 11px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS["accent_primary"]};
                border-radius: 6px;
            }}
            QStatusBar {{
                background-color: {COLORS["bg_card"]};
                color: {COLORS["text_primary"]};
                border-top: 1px solid {COLORS["border"]};
                padding: 5px;
                font-size: 11px;
            }}
            QFrame#separator {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(6,182,212,0),
                    stop:0.5 {COLORS["accent_primary"]},
                    stop:1 rgba(6,182,212,0)
                );
                max-height: 2px;
                margin: 10px 0;
            }}
            QLabel {{
                color: {COLORS["text_secondary"]};
                font-size: 11px;
            }}
            QScrollBar:vertical {{
                background-color: {COLORS["bg_secondary"]};
                width: 12px;
                border-radius: 6px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS["border"]};
                border-radius: 6px;
                min-height: 25px;
                margin: 1px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {COLORS["accent_primary"]};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            QScrollBar:horizontal {{
                background-color: {COLORS["bg_secondary"]};
                height: 12px;
                border-radius: 6px;
                margin: 2px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {COLORS["border"]};
                border-radius: 6px;
                min-width: 25px;
                margin: 1px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: {COLORS["accent_primary"]};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0px;
            }}
        """)

    def center_window(self):
        """窗口居中显示"""
        screen = QApplication.primaryScreen()
        screen_geometry = screen.geometry()
        window_geometry = self.geometry()
        
        x = (screen_geometry.width() - window_geometry.width()) // 2
        y = (screen_geometry.height() - window_geometry.height()) // 2
        
        self.move(x, y)

    def create_group_box(self, title: str) -> QGroupBox:
        """创建分组框"""
        group = QGroupBox(title)
        # 计算标题宽度，用于居中对齐
        font = QFont("Segoe UI", 15, QFont.Weight.Bold)
        fm = QFontMetrics(font)
        title_width = fm.horizontalAdvance(title)
        margin_left = -title_width // 2
        
        group.setStyleSheet(f"""
        .QGroupBox {{
            background-color: {COLORS['bg_card']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
            border-radius: 12px;
            margin-top: 20px;
            font-weight: bold;
            padding-top: 20px;
            font-size: 15px;
        }}
        .QGroupBox::title {{
            subcontrol-origin: margin;
            left: 50%;
            margin-left: {margin_left}px;
            padding: 0 10px;
            color: {COLORS['accent_primary']};
            font-size: 15px;
            font-weight: bold;
        }}""")
        return group

    def create_label(self, text: str) -> QLabel:
        """创建标签"""
        label = QLabel(text)
        label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; font-size: 11px;")
        label.setFixedHeight(30)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return label

    def create_button(self, text: str, btn_type: str = "default") -> QPushButton:
        """创建按钮"""
        btn = QPushButton(text)
        if btn_type != "default":
            btn.setObjectName(btn_type)
        btn.setFixedHeight(30)
        return btn

    def create_line_edit(self, placeholder: str, width: Optional[int] = None) -> QLineEdit:
        """创建文本输入框"""
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        edit.setFixedHeight(30)
        if width:
            edit.setFixedWidth(width)
        # 确保应用背景色
        edit.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: {COLORS['accent_primary']};
                font-size: 11px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['accent_primary']};
            }}
        """)
        return edit

    def create_date_edit(self) -> QDateEdit:
        """创建日期选择器"""
        edit = QDateEdit(calendarPopup=True)
        edit.setDisplayFormat("yyyy-MM-dd")
        edit.setCalendarPopup(True)
        edit.setFixedHeight(34)
        edit.setFixedWidth(160)
        # 确保应用背景色
        edit.setStyleSheet(f"""
            QDateEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 8px 12px;
                selection-background-color: {COLORS['accent_primary']};
                font-size: 12px;
                font-weight: 500;
                transition: all 0.2s ease;
            }}
            QDateEdit:focus {{
                border-color: {COLORS['accent_primary']};
                background-color: {COLORS['bg_card']};
                box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2);
            }}
            QDateEdit::drop-down {{
                border: none;
                background-color: {COLORS['bg_secondary']};
                width: 30px;
                border-radius: 0 8px 8px 0;
            }}
            QDateEdit::drop-down:hover {{
                background-color: {COLORS['bg_card']};
            }}
            QDateEdit::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid {COLORS['accent_primary']};
                margin-right: 10px;
                margin-top: 2px;
            }}
            QCalendarWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
            QCalendarWidget QWidget {{
                alternate-background-color: {COLORS['bg_card']};
            }}
            QCalendarWidget QHeaderView {{ 
                background-color: {COLORS['bg_card']};
                color: {COLORS['accent_primary']};
                font-weight: bold;
            }}
            QCalendarWidget QDayOfWeekRow {{ 
                background-color: {COLORS['bg_card']};
            }}
            QCalendarWidget QAbstractItemView:selected {{
                background-color: {COLORS['accent_primary']};
                color: {COLORS['bg_primary']};
            }}
            QCalendarWidget QAbstractItemView:hover:!selected {{
                background-color: {COLORS['bg_card']};
            }}
        """)
        return edit

    def create_combo_box(self, items: list) -> QComboBox:
        """创建下拉框"""
        combo = QComboBox()
        combo.addItems(items)
        combo.setFixedHeight(30)
        # 确保应用背景色
        combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 11px;
            }}
            QComboBox:focus {{
                border-color: {COLORS['accent_primary']};
            }}
            QComboBox::drop-down {{
                border: none;
                background-color: {COLORS['bg_secondary']};
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid {COLORS['accent_primary']};
                margin-right: 8px;
            }}
        """)
        return combo

    def create_table_widget(self) -> QTableWidget:
        """创建表格"""
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["📝 名称", "📅 日期", "🌐 来源", "⚠️ 等级"])
        table.setSelectionBehavior(table.SelectionBehavior.SelectRows)
        table.setEditTriggers(table.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.cellClicked.connect(self.show_detail)
        # 添加右键菜单支持
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_table_menu)

        header = table.horizontalHeader()
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self.show_header_menu)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 110)
        header.resizeSection(2, 120)
        header.resizeSection(3, 90)

        return table

    def create_text_browser(self) -> QTextBrowser:
        """创建文本浏览器"""
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setPlaceholderText("👈 点击左侧漏洞查看详情...")
        return browser

    # ------------------------------------------------------------------
    # 表头右键菜单：显示/隐藏列
    # ------------------------------------------------------------------
    def show_header_menu(self, pos):
        header = self.table.horizontalHeader()
        titles = ["名称", "日期", "来源", "等级"]
        menu = QMenu(self)
        for idx, title in enumerate(titles):
            act = menu.addAction(title)
            act.setCheckable(True)
            act.setChecked(not header.isSectionHidden(idx))
            act.toggled.connect(lambda chk, i=idx: header.showSection(i) if chk else header.hideSection(i))
        menu.exec(header.mapToGlobal(pos))

    # ------------------------------------------------------------------
    # 表格右键菜单：导出功能
    # ------------------------------------------------------------------
    def show_table_menu(self, pos):
        menu = QMenu(self)
        
        # 导出全部
        export_all_act = menu.addAction("导出全部")
        export_all_act.triggered.connect(self.export_all)
        
        # 导出时间范围
        export_date_act = menu.addAction("导出时间范围")
        export_date_act.triggered.connect(self.export_by_date)
        
        # 导出单条
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            export_single_act = menu.addAction("导出单条")
            export_single_act.triggered.connect(self.export_single)
        
        menu.exec(self.table.mapToGlobal(pos))

    # ------------------------------------------------------------------
    # 认证相关
    # ------------------------------------------------------------------
    def _on_src_change(self):
        hint = "粘贴 GitHub Token (PAT)" if self.src_combo.currentText() == "GitHub" else "粘贴整串 Cookie"
        self.auth_edit.setPlaceholderText(hint)

    def apply_auth(self):
        txt = self.auth_edit.text().strip()
        src = self.src_combo.currentText()

        if src == "ThreatBook":
            threatbook.set_cookie(txt)
        else:  # GitHub
            set_github_token(txt or None)
            cfg = load_cfg()
            if txt:
                cfg["github_token"] = txt
            else:
                cfg.pop("github_token", None)
            save_cfg(cfg)
        self._flash(self.auth_btn)

    # ------------------------------------------------------------------
    # 代理相关
    # ------------------------------------------------------------------
    def apply_proxy(self):
        set_proxy(self.http_edit.text().strip() or None, self.https_edit.text().strip() or None)
        self._flash(self.proxy_btn)

    def test_proxy(self):
        http_url = self.http_edit.text().strip() or None
        https_url = self.https_edit.text().strip() or None

        def worker():
            s = requests.Session()
            from utils import _normalize

            http_proxy = _normalize(http_url, "http")
            https_proxy = _normalize(https_url, "https")
            if http_proxy:
                s.proxies["http"] = http_proxy
            if https_proxy:
                s.proxies["https"] = https_proxy

            try:
                r = s.get("http://httpbin.org/ip", timeout=5)
                r.raise_for_status()
                msg = f"代理可用，外网 IP: {r.json().get('origin')}"
            except Exception as exc:
                msg = f"代理不可用：{exc}"

            self.proxy_test_done.emit(msg)

        threading.Thread(target=worker, daemon=True).start()

    def _show_proxy_msg(self, msg: str):
        QMessageBox.information(self, "代理测试结果", msg)

    def test_data_sources(self):
        """测试所有数据源的有效性"""
        self.update_status("正在测试数据源...", "loading")
        
        def worker():
            data_sources = [
                ("长亭 Rivers", "changtin", "fetch_changtin"),
                ("OSCS", "oscs", "fetch_oscs"),
                ("奇安信", "qianxin", "fetch_qianxin"),
                ("ThreatBook", "threatbook", "fetch_threatbook"),
                ("CISA", "cisa", "fetch_cisa"),
            ]
            
            results = {}
            for name, module_name, function_name in data_sources:
                try:
                    module = __import__(module_name)
                    fetch_function = getattr(module, function_name)
                    # 测试函数是否存在且可调用
                    if callable(fetch_function):
                        # 尝试获取今天和昨天的数据
                        import datetime
                        today = datetime.date.today().isoformat()
                        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
                        
                        # 测试今天的数据
                        vulns_today = fetch_function(today)
                        # 测试昨天的数据
                        vulns_yesterday = fetch_function(yesterday)
                        # 合并结果
                        vulns = vulns_today + vulns_yesterday
                        results[name] = {
                            "status": "有效",
                            "count": len(vulns),
                            "today_count": len(vulns_today),
                            "yesterday_count": len(vulns_yesterday)
                        }
                    else:
                        results[name] = {
                            "status": "无效",
                            "error": "函数不可调用"
                        }
                except Exception as e:
                    results[name] = {
                        "status": "无效",
                        "error": str(e)
                    }
            
            # 构建消息
            msg = "数据源测试结果：\n\n"
            for name, result in results.items():
                if result["status"] == "有效":
                    msg += f"✅ {name}: 有效 (今天: {result.get('today_count', 0)} 条, 昨天: {result.get('yesterday_count', 0)} 条, 总计: {result['count']} 条)\n"
                else:
                    msg += f"❌ {name}: 无效 - {result['error']}\n"
            
            # 通过信号在主线程中显示消息
            self.sources_test_done.emit(msg)
            self.update_status("数据源测试完成", "success")
        
        # 在后台线程中执行测试
        threading.Thread(target=worker, daemon=True).start()
        
    def _show_sources_msg(self, msg: str):
        """在主线程中显示数据源测试结果"""
        QMessageBox.information(self, "数据源测试", msg)

    # ------------------------------------------------------------------
    # 搜索
    # ------------------------------------------------------------------
    def search_vulns_gui(self):
        keyword = self.search_edit.text().strip()
        if not keyword:
            QMessageBox.warning(self, "输入错误", "请输入要搜索的 CVE 编号或漏洞名称！")
            return

        if self.timer.isActive():
            self.timer.stop()

        self.full_data.clear()
        self.table.setRowCount(0)
        self.detail_box.clear()

        self.refresh_btn.setEnabled(False)
        self.search_btn.setEnabled(False)
        self.update_status(f"正在搜索：{keyword}...", "loading")

        def worker():
            vulns = search_vulns(keyword)
            self.search_finished.emit(vulns)

        threading.Thread(target=worker, daemon=True).start()

    def handle_search_results(self, vulns):
        self.refresh_btn.setEnabled(True)
        self.search_btn.setEnabled(True)

        if not vulns:
            QMessageBox.information(self, "无结果", "未找到匹配的漏洞！")
            if not self.timer.isActive():
                self.timer.start(30 * 60 * 1000)
            self.update_status("搜索完成，无结果", "warning")
            return

        self.full_data = vulns
        self.page = 0
        self.update_table()
        self.update_status(f"搜索到 {len(vulns)} 条结果", "success")
    # ------------------------------------------------------------------
    # 数据抓取
    # ------------------------------------------------------------------
    def load_data(self):
        if not self._mtx.tryLock():
            return

        self.set_loading(True)
        self.update_status("正在爬取漏洞数据...", "loading")

        start_date = self.date_from.date().toPyDate()
        end_date = self.date_to.date().toPyDate()
        if start_date > end_date:
            QMessageBox.warning(self, "日期错误", "起始日期不能晚于结束日期！")
            self.refresh_btn.setEnabled(True)
            self._mtx.unlock()
            self.set_loading(False)
            return

        def worker():
            data: list[VulnItem] = []
            cursor = start_date
            total_days = (end_date - start_date).days + 1
            processed = 0
            
            while cursor <= end_date:
                day_str = cursor.isoformat()
                data.extend(fetch_all(day_str, DATE_FETCHERS))
                cursor += dt.timedelta(days=1)
                processed += 1
                # 更新进度（通过信号槽）
            
            self.data_ready.emit(data)

        threading.Thread(target=worker, daemon=True).start()

    def on_data_ready(self, data: list[VulnItem]):
        self.full_data = sorted(data, key=lambda v: v.name)
        self.page = 0
        self.update_table()
        self._mtx.unlock()
        self.set_loading(False)
        
        if data and not self.timer.isActive():
            self.timer.start(30 * 60 * 1000)  # 30‑min auto‑refresh
        
        self.update_status(f"数据加载完成，共 {len(data)} 条漏洞", "success")

    # ------------------------------------------------------------------
    # 导出功能
    # ------------------------------------------------------------------
    def export_all(self):
        """导出所有漏洞"""
        if not self.full_data:
            QMessageBox.information(self, "提示", "没有数据可导出")
            return
        
        self._export_vulns(self.full_data, "all")

    def export_by_date(self):
        """导出时间范围内的漏洞"""
        if not self.full_data:
            QMessageBox.information(self, "提示", "没有数据可导出")
            return
        
        # 创建日期选择对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("选择导出时间范围")
        dialog.setMinimumWidth(400)
        
        # 应用现代化样式
        style_sheet = """
            QDialog {
                background-color: %s;
                color: %s;
                border-radius: 12px;
            }
            QLabel {
                color: %s;
                font-size: 12px;
                font-weight: 500;
            }
            QDateEdit {
                background-color: %s;
                color: %s;
                border: 1px solid %s;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: %s;
                selection-color: %s;
                font-size: 11px;
            }
            QDateEdit:focus {
                border-color: %s;
                background-color: %s;
            }
            QDateEdit::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid %s;
                margin-right: 8px;
            }
            QPushButton {
                background-color: %s;
                color: %s;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11px;
                min-width: 80px;
                transition: all 0.2s ease;
            }
            QPushButton:hover {
                background-color: #0891b2;
                transform: translateY(-1px);
            }
            QPushButton:pressed {
                background-color: #0891b2;
                transform: translateY(0);
            }
        """ % (COLORS["bg_secondary"], COLORS["text_primary"],
                COLORS["text_primary"],
                COLORS["bg_card"], COLORS["text_primary"], COLORS["border"],
                COLORS["accent_primary"], COLORS["bg_primary"],
                COLORS["accent_primary"], COLORS["bg_primary"],
                COLORS["accent_primary"],
                COLORS["accent_primary"], COLORS["bg_primary"])
        
        dialog.setStyleSheet(style_sheet)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # 起始日期
        date_layout = QHBoxLayout()
        date_layout.addWidget(QLabel("起始日期:"))
        export_start_date = QDateEdit()
        export_start_date.setCalendarPopup(True)
        export_start_date.setDate(self.date_from.date())
        export_start_date.setFixedWidth(150)
        date_layout.addWidget(export_start_date)
        layout.addLayout(date_layout)
        
        # 结束日期
        date_layout2 = QHBoxLayout()
        date_layout2.addWidget(QLabel("结束日期:"))
        export_end_date = QDateEdit()
        export_end_date.setCalendarPopup(True)
        export_end_date.setDate(self.date_to.date())
        export_end_date.setFixedWidth(150)
        date_layout2.addWidget(export_end_date)
        layout.addLayout(date_layout2)
        
        # 按钮
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(dialog.accept)
        ok_btn.setFixedWidth(80)
        button_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(dialog.reject)
        cancel_btn.setFixedWidth(80)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # 显示对话框
        if dialog.exec() == QDialog.DialogCode.Accepted:
            start_date = export_start_date.date().toString("yyyy-MM-dd")
            end_date = export_end_date.date().toString("yyyy-MM-dd")
            
            # 验证日期范围
            if start_date > end_date:
                QMessageBox.warning(self, "警告", "起始日期不能大于结束日期")
                return
            
            # 筛选数据
            filtered_data = [vuln for vuln in self.full_data if start_date <= vuln.date <= end_date]
            if not filtered_data:
                QMessageBox.information(self, "提示", f"{start_date} 到 {end_date} 期间没有数据")
                return
            
            self._export_vulns(filtered_data, f"date_{start_date}_{end_date}")

    def export_single(self):
        """导出选中的单条漏洞"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "提示", "请先选择一条漏洞")
            return
        
        row = selected_rows[0].row()
        start = self.page * PAGE_SIZE
        vuln = self.full_data[start + row]
        
        self._export_vulns([vuln], f"single_{vuln.cve or vuln.name[:20].replace(' ', '_')}")

    # ------------------------------------------------------------------
    # 日期范围设置
    # ------------------------------------------------------------------
    def set_date_range(self, start_date: dt.date, end_date: dt.date):
        """设置日期范围"""
        self.date_from.setDate(start_date)
        self.date_to.setDate(end_date)

    def _export_vulns(self, vulns: List[VulnItem], filename_prefix: str):
        """导出漏洞数据"""
        import os
        
        # 创建导出目录
        export_dir = "exports"
        os.makedirs(export_dir, exist_ok=True)
        
        # 生成文件名
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{export_dir}/{filename_prefix}_{timestamp}"
        
        # 导出为 JSON
        json_filename = f"{filename}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump([
                {
                    "name": vuln.name,
                    "cve": vuln.cve,
                    "date": vuln.date,
                    "severity": vuln.severity,
                    "tags": vuln.tags,
                    "source": vuln.source,
                    "description": vuln.description,
                    "reference": vuln.reference
                }
                for vuln in vulns
            ], f, ensure_ascii=False, indent=2)
        
        # 导出为 CSV
        csv_filename = f"{filename}.csv"
        with open(csv_filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["名称", "CVE编号", "日期", "严重程度", "标签", "来源", "描述", "参考链接"])
            for vuln in vulns:
                writer.writerow([
                    vuln.name,
                    vuln.cve or "",
                    vuln.date,
                    vuln.severity,
                    vuln.tags or "",
                    vuln.source,
                    vuln.description or "",
                    "\n".join(vuln.reference) if vuln.reference else ""
                ])
        
        QMessageBox.information(self, "导出成功", f"已导出到:\n{json_filename}\n{csv_filename}")

    # ------------------------------------------------------------------
    # UI 辅助
    # ------------------------------------------------------------------
    def update_status(self, message: str, status_type: str = "info"):
        """更新状态栏"""
        colors = {
            "info": "#00d4ff",
            "success": "#00ff9d",
            "warning": "#ffb86c",
            "error": "#ff5555",
            "loading": "#f1fa8c",
        }
        color = colors.get(status_type, colors["info"])
        self.status_label.setText(f"● {message}")
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def set_loading(self, loading: bool):
        """设置加载状态"""
        if loading:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # 无限循环
            self.refresh_btn.setEnabled(False)
            self.search_btn.setEnabled(False)
        else:
            self.progress_bar.setVisible(False)
            self.refresh_btn.setEnabled(True)
            self.search_btn.setEnabled(True)

    def _flash(self, btn: QPushButton):
        """按钮闪烁动画"""
        original_style = btn.styleSheet()
        btn.setStyleSheet(f"background-color: {COLORS['accent_primary']}; color: {COLORS['bg_primary']};")
        QTimer.singleShot(300, lambda: btn.setStyleSheet(original_style))

    def reset_view(self):
        self.detail_box.clear()
        self.table.clearSelection()

    def update_table(self):
        start = self.page * PAGE_SIZE
        rows = self.full_data[start : start + PAGE_SIZE]

        self.table.setRowCount(len(rows))
        for r, v in enumerate(rows):
            for c, text in enumerate([v.name, v.date, v.source, v.severity or ""]):
                itm = QTableWidgetItem(text)
                if c == 3 and v.severity in SEV_COLOR:
                    itm.setForeground(SEV_COLOR[v.severity])
                    itm.setBackground(QColor(COLORS["bg_secondary"]))
                self.table.setItem(r, c, itm)

        total_pages = max(1, (len(self.full_data) + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_label.setText(f"第 {self.page + 1} 页，共 {total_pages} 页")
        
        # 更新按钮状态
        has_data = len(self.full_data) > 0
        self.first_btn.setEnabled(has_data and self.page > 0)
        self.prev_btn.setEnabled(has_data and self.page > 0)
        self.next_btn.setEnabled(has_data and start + PAGE_SIZE < len(self.full_data))
        self.last_btn.setEnabled(has_data and self.page < total_pages - 1)
        
        self.count_label.setText(f"共 {len(self.full_data)} 条漏洞")

    def change_page(self, delta: int):
        self.page += delta
        self.update_table()

    def go_to_last_page(self):
        """跳转到最后一页"""
        if not self.full_data:
            return
        total_pages = (len(self.full_data) + PAGE_SIZE - 1) // PAGE_SIZE
        self.page = total_pages - 1
        self.update_table()

    # ------------------------------------------------------------------
    # 详情
    # ------------------------------------------------------------------
    def _append_html(self, html: str):
        cursor = self.detail_box.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertHtml(html)
        self.detail_box.setTextCursor(cursor)

    def show_detail(self, row: int, _col: int):
        idx = self.page * PAGE_SIZE + row
        item = self.full_data[idx]

        # 基本信息
        self._click_token += 1
        token = self._click_token
        self.detail_box.setHtml("<br>".join(escape(item.display_block()).splitlines()))

        # 异步搜索 GitHub PoC
        def worker():
            try:
                urls = fetch_poc_urls(item.cve, item.name, item.cve or item.tags)[:2]
            except Exception as exc:
                print("[PoC] error:", exc)
                urls = []
            if not urls or token != self._click_token:
                return
            links = "<br>".join(f'<a href="{u}">{u}</a>' for u in urls)
            self.add_html.emit(f"<br><b>[PoC/EXP]</b><br>{links}")

        threading.Thread(target=worker, daemon=True).start()


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
