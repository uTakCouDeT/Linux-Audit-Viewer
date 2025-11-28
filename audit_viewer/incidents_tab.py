from PyQt5 import QtWidgets, QtCore

from .models import PlaceholderTableView, AuditEventsTableModel
from .incidents import find_ssh_bruteforce, find_critical_file_changes, find_web_shell, CRITICAL_PATHS


class IncidentsTabMixin:
    """Методы, относящиеся к вкладке 'Инциденты'."""

    def _init_incidents_tab(self):
        """Вкладка 'Инциденты': список сценариев + результаты + описание + детали."""
        main_layout = QtWidgets.QHBoxLayout()
        self.incidents_tab.setLayout(main_layout)

        # --- ЛЕВО: список сценариев ---
        left_panel = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout()
        left_panel.setLayout(left_layout)

        self.incidents_list = QtWidgets.QListWidget()
        self.incidents_list.addItem("Подбор пароля по SSH")
        self.incidents_list.addItem("Изменения критичных файлов")
        self.incidents_list.addItem("Web-shell (shell от сервисного пользователя)")

        left_layout.addWidget(QtWidgets.QLabel("Сценарии инцидентов:"))
        left_layout.addWidget(self.incidents_list)
        left_layout.addStretch()

        # Пока, пока нет событий, логично отключить список
        self.incidents_list.setEnabled(False)

        # --- ПРАВО: результаты + описание + детали ---
        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Таблица результатов
        self.incidents_table = PlaceholderTableView()
        self.incidents_table.setPlaceholderText("Выберите сценарий и загрузите события на вкладке 'События'.")

        # Панель деталей (как на вкладке событий, но отдельная)
        details_widget = QtWidgets.QWidget()
        details_layout = QtWidgets.QVBoxLayout()
        details_widget.setLayout(details_layout)

        self.incident_description = QtWidgets.QTextEdit()
        self.incident_description.setReadOnly(True)
        self.incident_description.setMinimumHeight(80)

        # Детали конкретного события
        self.incident_details = self._create_event_details_widget_for_incidents()

        details_layout.addWidget(QtWidgets.QLabel("Описание сценария:"))
        details_layout.addWidget(self.incident_description)
        details_layout.addWidget(self.incident_details)

        right_splitter.addWidget(self.incidents_table)
        right_splitter.addWidget(details_widget)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 2)

        # Главный горизонтальный сплиттер
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_splitter)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 4)

        main_layout.addWidget(main_splitter)

        # Сигналы
        self.incidents_list.currentRowChanged.connect(self._on_incident_scenario_selected)

    def _create_event_details_widget_for_incidents(self) -> QtWidgets.QWidget:
        """Создаёт виджет панели деталей события для вкладки 'Инциденты'."""
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        widget.setLayout(layout)

        tabs = QtWidgets.QTabWidget()

        # Вкладка "Структура"
        structured_tab = QtWidgets.QWidget()
        structured_layout = QtWidgets.QVBoxLayout()
        structured_tab.setLayout(structured_layout)

        self.incident_details_table = QtWidgets.QTableWidget()
        self.incident_details_table.setColumnCount(2)
        self.incident_details_table.setHorizontalHeaderLabels(["Поле", "Значение"])
        self.incident_details_table.horizontalHeader().setStretchLastSection(True)

        structured_layout.addWidget(self.incident_details_table)

        # Вкладка "Сырой лог"
        raw_tab = QtWidgets.QWidget()
        raw_layout = QtWidgets.QVBoxLayout()
        raw_tab.setLayout(raw_layout)

        self.incident_raw_text_edit = QtWidgets.QPlainTextEdit()
        self.incident_raw_text_edit.setReadOnly(True)
        raw_layout.addWidget(self.incident_raw_text_edit)

        tabs.addTab(structured_tab, "Структура")
        tabs.addTab(raw_tab, "Сырой лог")

        layout.addWidget(tabs)

        return widget

    def _on_incident_scenario_selected(self, row: int):
        """Вызывается при выборе сценария в списке слева."""
        if not self.all_events:
            self.incident_description.setPlainText("Сначала загрузите события на вкладке 'События'.")
            self._update_incidents_view([])
            return

        if row < 0:
            self.incident_description.clear()
            self._update_incidents_view([])
            return

        # Выбираем сценарий по индексу
        if row == 0:
            # Подбор пароля по SSH
            desc = (
                "Сценарий: Подбор пароля по SSH\n\n"
                "Ищутся серии неуспешных событий USER_AUTH/USER_LOGIN, связанных с sshd, "
                "где в течение короткого интервала времени происходит несколько (>= 5) "
                "ошибок аутентификации для одного пользователя или одного IP-адреса."
            )
            incidents = find_ssh_bruteforce(self.all_events)
        elif row == 1:
            # Изменение критичных файлов
            desc = (
                "Сценарий: Изменения критичных файлов\n\n"
                "Ищутся успешные системные вызовы (SYSCALL), связанные с путями:\n"
                f"{', '.join(CRITICAL_PATHS)}\n"
                "Такие изменения могут указывать на изменение конфигурации системы, паролей и прав."
            )
            incidents = find_critical_file_changes(self.all_events)
        elif row == 2:
            # Web-shell
            desc = (
                "Сценарий: Web-shell (запуск shell от сервисного пользователя)\n\n"
                "Ищутся запуск командных оболочек (bash/sh) через execve от имени сервисных "
                "пользователей (www-data/nginx/apache и т.п.). Это может указывать на эксплуатацию "
                "уязвимости в веб-приложении и получение удалённого доступа к системе."
            )
            incidents = find_web_shell(self.all_events)
        else:
            desc = ""
            incidents = []

        self.incident_description.setPlainText(desc)
        self._set_incident_results(incidents)

    def _set_incident_results(self, events):
        """Сохраняет текущий список событий-инцидентов и обновляет таблицу на вкладке 'Инциденты'."""
        self.incident_events = events or []

        model = AuditEventsTableModel(self.incident_events, self)
        self.incidents_table.setModel(model)

        header = self.incidents_table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        # переподключаем обработчик выбора
        selection_model = self.incidents_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_incident_selection_changed)

        # очищаем детали
        self._clear_incident_details()

    def _update_incidents_view(self, events):
        """Обновляет только таблицу (для пустого состояния и т.п.)."""
        self.incident_events = events or []
        model = AuditEventsTableModel(self.incident_events, self)
        self.incidents_table.setModel(model)
        header = self.incidents_table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self._clear_incident_details()

    def _on_incident_selection_changed(self, selected, deselected):
        """Обновляет детали инцидента при выборе строки в таблице результатов."""
        indexes = selected.indexes()
        if not indexes:
            self._clear_incident_details()
            return

        row = indexes[0].row()
        if not (0 <= row < len(self.incident_events)):
            self._clear_incident_details()
            return

        event = self.incident_events[row]
        details = event.get("details", {})

        self.incident_details_table.setRowCount(len(details))

        for i, (field, value) in enumerate(details.items()):
            field_item = QtWidgets.QTableWidgetItem(str(field))
            value_item = QtWidgets.QTableWidgetItem(str(value))
            self.incident_details_table.setItem(i, 0, field_item)
            self.incident_details_table.setItem(i, 1, value_item)

        self.incident_raw_text_edit.setPlainText(event.get("raw", ""))

    def _clear_incident_details(self):
        self.incident_details_table.setRowCount(0)
        self.incident_raw_text_edit.clear()
