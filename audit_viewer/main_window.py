from PyQt5 import QtWidgets
from pathlib import Path
import sys, json, subprocess

from .parser import parse_audit_log_file

from .events_tab import EventsTabMixin
from .incidents_tab import IncidentsTabMixin
from .stats_tab import StatsTabMixin


class MainWindow(QtWidgets.QMainWindow, EventsTabMixin, IncidentsTabMixin, StatsTabMixin):
    def __init__(self):
        super().__init__()

        self.all_events = []
        self.incident_events = []

        self.setWindowTitle("Linux Audit Viewer")
        self.resize(1200, 800)

        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QtWidgets.QVBoxLayout()
        central_widget.setLayout(main_layout)

        self.tab_widget = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tab_widget)

        self._create_tabs()
        self._create_menu()
        self._create_status_bar()

    def _set_events(self, events):
        self.all_events = events or []

        if not self.all_events:
            self.apply_filter_btn.setEnabled(False)
            self.reset_filter_btn.setEnabled(False)
            self.incidents_list.setEnabled(False)
            self._update_events_view([])
            self.statusBar().showMessage("События не загружены")
            self._update_stats_controls_state()
            return

        self.apply_filter_btn.setEnabled(True)
        self.reset_filter_btn.setEnabled(True)
        self.incidents_list.setEnabled(True)

        # --- обновляем список пользователей ---
        users = sorted({ev.get("user") for ev in self.all_events if ev.get("user")})
        self.user_combo.blockSignals(True)
        self.user_combo.clear()
        self.user_combo.addItem("Любой")
        for u in users:
            self.user_combo.addItem(u)
        self.user_combo.blockSignals(False)

        # --- обновляем список типов событий ---
        types = sorted({ev.get("event_type") for ev in self.all_events if ev.get("event_type")})
        self.type_combo.blockSignals(True)
        self.type_combo.clear()
        self.type_combo.addItem("Любой")
        for t in types:
            self.type_combo.addItem(t)
        self.type_combo.blockSignals(False)

        # --- обновляем временные фильтры по min/max ---
        self._update_time_filters_from_events()

        # применяем фильтры к новому набору
        self._apply_filters()

        # --- вкладка 'Статистика' ---
        self._update_stats_controls_state()
        self._update_stats_time_filters_from_events()
        self._recalculate_stats()

    def _load_data_from_file(self, path: str):
        """
        Загружает события из указанного файла журнала auditd (офлайн-режим).
        """
        try:
            events = parse_audit_log_file(path)
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось прочитать или распарсить файл:\n{path}\n\n{e}",
            )
            self.statusBar().showMessage("Ошибка при загрузке файла журнала")
            return

        if not events:
            QtWidgets.QMessageBox.information(
                self,
                "Информация",
                f"В файле {path} не найдено ни одного события."
            )
            self.statusBar().showMessage("Файл журнала не содержит событий")
            # Пустой список — обновим таблицу, покажется плейсхолдер
            self._set_events([])
            return

        self._set_events(events)
        self.statusBar().showMessage(f"Загружено событий из файла: {path} ({len(events)})")

    def _open_log_file_dialog(self):
        """
        Открывает диалог выбора файла журнала auditd и загружает выбранный файл.
        """
        dlg = QtWidgets.QFileDialog(self, "Выберите файл журнала аудита")
        dlg.setFileMode(QtWidgets.QFileDialog.ExistingFile)
        dlg.setNameFilters([
            "Логи auditd (*.log)",
            "Все файлы (*)",
        ])

        if dlg.exec_():
            selected_files = dlg.selectedFiles()
            if selected_files:
                path = selected_files[0]
                self._load_data_from_file(path)

    def _load_data_with_pkexec(self):
        """
        Запускает helper через pkexec для чтения /var/log/audit/audit.log с правами root.
        """
        python_exe = sys.executable
        helper_path = Path(__file__).resolve().parent.parent / "audit_helper.py"

        try:
            output = subprocess.check_output(
                ["pkexec", python_exe, helper_path],
                stderr=subprocess.STDOUT,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            QtWidgets.QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось выполнить helper:\n{e.output}",
            )
            return
        except FileNotFoundError:
            QtWidgets.QMessageBox.warning(
                self,
                "Ошибка",
                "pkexec не найден. Установите polkit или используйте офлайн-режим."
            )
            return

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            QtWidgets.QMessageBox.warning(
                self,
                "Ошибка",
                "Helper вернул некорректный JSON."
            )
            return

        if "error" in data:
            QtWidgets.QMessageBox.warning(
                self,
                "Ошибка",
                f"Helper сообщил об ошибке: {data.get('error')}\n{data.get('message', '')}"
            )
            return

        events = data.get("events", [])
        if not events:
            QtWidgets.QMessageBox.information(
                self,
                "Информация",
                "В журнале не найдено событий."
            )
            self._set_events([])
            return

        self._set_events(events)
        self.statusBar().showMessage(
            f"Загружено событий из системного журнала (root): {len(events)}"
        )

    def _create_tabs(self):
        self.events_tab = QtWidgets.QWidget()
        self._init_events_tab()
        self.tab_widget.addTab(self.events_tab, "События аудита")

        self.incidents_tab = QtWidgets.QWidget()
        self._init_incidents_tab()
        self.tab_widget.addTab(self.incidents_tab, "Инциденты")

        self.stats_tab = QtWidgets.QWidget()
        self._init_stats_tab()
        self.tab_widget.addTab(self.stats_tab, "Статистика")

        # self.settings_tab = QtWidgets.QWidget()
        # settings_layout = QtWidgets.QVBoxLayout()
        # settings_layout.addWidget(QtWidgets.QLabel("Здесь будут настройки пути к логам и БД"))
        # self.settings_tab.setLayout(settings_layout)
        # self.tab_widget.addTab(self.settings_tab, "Настройки")

    def _create_menu(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("Файл")

        # --- Новый пункт: открыть журнал из локального файла ---
        open_file_action = QtWidgets.QAction("Открыть журнал из файла...", self)
        open_file_action.triggered.connect(self._open_log_file_dialog)
        file_menu.addAction(open_file_action)

        # --- Уже существующий пункт: загрузить системный журнал (root) ---
        load_root_action = QtWidgets.QAction("Загрузить системный журнал (root)", self)
        load_root_action.triggered.connect(self._load_data_with_pkexec)
        file_menu.addAction(load_root_action)

        file_menu.addSeparator()

        exit_action = QtWidgets.QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menu_bar.addMenu("Справка")
        about_action = QtWidgets.QAction("О программе", self)
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)

    def _create_status_bar(self):
        status_bar = self.statusBar()
        status_bar.showMessage("Готово")  # простой текст внизу окна

    def _show_about_dialog(self):
        QtWidgets.QMessageBox.information(
            self,
            "О программе",
            "Linux Audit Viewer\nКурсовой проект: программа для визуализации логов auditd",
        )
