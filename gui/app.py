"""
RecoverX Main Desktop Application Window (Premium Light Redesign)
Hosts the modern light-themed PySide6 application, sidebar navigation, top session bar,
bottom status footer, and 7 core views matching the Stitch reference design.
"""
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QStackedWidget, QFrame, QLabel, QStatusBar
)
from PySide6.QtCore import Qt
import sys

from gui.theme import LIGHT_THEME_QSS
from gui.widgets.sidebar import SidebarNavigation
from gui.views.dashboard_view import DashboardView
from gui.views.recover_files_view import RecoverFilesView
from gui.views.android_view import AndroidView
from gui.views.whatsapp_view import WhatsAppView
from gui.views.history_view import HistoryView
from gui.views.reports_view import ReportsView
from gui.views.settings_view import SettingsView

class RecoverXMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RecoverX — Forensic Data Recovery Engine")
        self.resize(1340, 860)
        self.setMinimumSize(1100, 720)
        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Session & Security Banner
        top_bar = QFrame()
        top_bar.setFixedHeight(34)
        top_bar.setStyleSheet("""
            background-color: #ffffff;
            border-bottom: 1px solid #e2e8f0;
        """)
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(16, 0, 16, 0)
        tb_layout.setSpacing(12)

        tb_title = QLabel("RecoverX — Forensic Data Recovery Engine")
        tb_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #334155;")

        tb_session = QLabel("SESSION: 0x9AF4-SECURE-AIRGAP")
        tb_session.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748b;")

        tb_ro_badge = QLabel("• SOFTWARE READ-ONLY ENFORCED")
        tb_ro_badge.setStyleSheet("font-size: 11px; font-weight: 700; color: #059669;")

        tb_layout.addWidget(tb_title)
        tb_layout.addWidget(QLabel("|", styleSheet="color: #cbd5e1;"))
        tb_layout.addWidget(tb_session)
        tb_layout.addWidget(tb_ro_badge)
        tb_layout.addStretch()

        root_layout.addWidget(top_bar)

        # 2. Main Content Splitter: Sidebar + Stacked Views
        body_container = QWidget()
        body_layout = QHBoxLayout(body_container)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Sidebar Navigation
        self.sidebar = SidebarNavigation(self)
        self.sidebar.navigation_changed.connect(self._on_navigation_changed)
        body_layout.addWidget(self.sidebar)

        # Right Stacked Views (7 views)
        self.stacked_views = QStackedWidget(self)

        self.view_dashboard = DashboardView(self)
        self.view_recover = RecoverFilesView(self)
        self.view_android = AndroidView(self)
        self.view_whatsapp = WhatsAppView(self)
        self.view_history = HistoryView(self)
        self.view_reports = ReportsView(self)
        self.view_settings = SettingsView(self)

        # Connect Dashboard Navigation Signals
        self.view_dashboard.navigate_to_recovery.connect(lambda: self._navigate_to_view(1))
        self.view_dashboard.navigate_to_history.connect(lambda: self._navigate_to_view(4))
        self.view_dashboard.navigate_to_settings.connect(lambda: self._navigate_to_view(6))

        self.stacked_views.addWidget(self.view_dashboard)   # 0
        self.stacked_views.addWidget(self.view_recover)     # 1
        self.stacked_views.addWidget(self.view_android)     # 2
        self.stacked_views.addWidget(self.view_whatsapp)    # 3
        self.stacked_views.addWidget(self.view_history)     # 4
        self.stacked_views.addWidget(self.view_reports)     # 5
        self.stacked_views.addWidget(self.view_settings)    # 6

        body_layout.addWidget(self.stacked_views, 1)
        root_layout.addWidget(body_container, 1)

        # 3. Bottom Global Status Bar
        bottom_bar = QFrame()
        bottom_bar.setFixedHeight(28)
        bottom_bar.setStyleSheet("""
            background-color: #ffffff;
            border-top: 1px solid #e2e8f0;
        """)
        bb_layout = QHBoxLayout(bottom_bar)
        bb_layout.setContentsMargins(16, 0, 16, 0)
        bb_layout.setSpacing(14)

        bb_left = QLabel("● OFFLINE AIR-GAP: ACTIVE  •  ADB: STANDBY (READ-ONLY)  •  SHA-256 INTEGRITY VERIFIED")
        bb_left.setStyleSheet("font-size: 11px; font-weight: 600; color: #059669;")

        bb_right = QLabel("SECTOR ZERO PROTECTED  •  BUILD 2026.11")
        bb_right.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748b; letter-spacing: 0.5px;")

        bb_layout.addWidget(bb_left)
        bb_layout.addStretch()
        bb_layout.addWidget(bb_right)

        root_layout.addWidget(bottom_bar)

    def _on_navigation_changed(self, index: int):
        self.stacked_views.setCurrentIndex(index)
        # Refresh dynamic content when navigating
        if index == 0:
            self.view_dashboard.refresh_data()
        elif index == 4:
            self.view_history.refresh_reports()
        elif index == 5:
            self.view_reports.refresh_data()

    def _navigate_to_view(self, index: int):
        self.sidebar.set_active_index(index)
        self.stacked_views.setCurrentIndex(index)

def launch_gui():
    """Starts the RecoverX PySide6 application."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(LIGHT_THEME_QSS)
    window = RecoverXMainWindow()
    window.show()
    return app.exec()

if __name__ == "__main__":
    sys.exit(launch_gui())
