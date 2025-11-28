from PyQt5 import QtWidgets, QtCore

from .models import PlaceholderTableView, AuditEventsTableModel


class EventsTabMixin:
    """Методы, относящиеся к вкладке 'События аудита'."""

    def _init_events_tab(self):
        """Вкладка 'События аудита': фильтры + таблица + детали."""
        main_layout = QtWidgets.QHBoxLayout()
        self.events_tab.setLayout(main_layout)

        # --- ЛЕВЫЙ СПЛИТТЕР: панель фильтров ---
        self.filters_panel = self._create_filters_panel()

        # --- ПРАВЫЙ СПЛИТТЕР: таблица + детали ---
        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Таблица событий с плейсхолдером
        self.events_table = PlaceholderTableView()
        self.events_table.setPlaceholderText('Загрузите данные в меню "Файл".')
        self.events_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.events_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.events_table.setSortingEnabled(True)
        self.events_table.setAlternatingRowColors(True)

        # Панель деталей события
        self.event_details = self._create_event_details_widget()

        right_splitter.addWidget(self.events_table)
        right_splitter.addWidget(self.event_details)
        right_splitter.setStretchFactor(0, 3)
        right_splitter.setStretchFactor(1, 1)

        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_splitter.addWidget(self.filters_panel)
        main_splitter.addWidget(right_splitter)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 3)

        main_layout.addWidget(main_splitter)

    def _init_events_tab(self):
        """Каркас вкладки 'События аудита': фильтры + таблица + детали."""
        main_layout = QtWidgets.QHBoxLayout()
        self.events_tab.setLayout(main_layout)

        # --- ЛЕВЫЙ СПЛИТТЕР: панель фильтров ---
        self.filters_panel = self._create_filters_panel()

        # --- ПРАВЫЙ СПЛИТТЕР: таблица + детали ---
        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Таблица событий (пока пустая)
        # Таблица событий с плейсхолдером
        self.events_table = PlaceholderTableView()
        self.events_table.setPlaceholderText('Загрузите данные в меню "Файл".')
        self.events_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.events_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.events_table.setSortingEnabled(True)
        self.events_table.setAlternatingRowColors(True)

        # Панель деталей события (пока заглушка)
        self.event_details = self._create_event_details_widget()

        # Добавляем в вертикальный сплиттер
        right_splitter.addWidget(self.events_table)
        right_splitter.addWidget(self.event_details)
        right_splitter.setStretchFactor(0, 3)  # таблица занимает больше места
        right_splitter.setStretchFactor(1, 1)  # детали меньше

        # --- ГЛАВНЫЙ СПЛИТТЕР: фильтры | (таблица+детали) ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        main_splitter.addWidget(self.filters_panel)
        main_splitter.addWidget(right_splitter)

        # задать пропорции: слева фильтры уже, справа контент шире
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 3)

        main_layout.addWidget(main_splitter)

    def _create_filters_panel(self) -> QtWidgets.QWidget:
        """Создаёт левую панель с фильтрами событий."""
        panel = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        panel.setLayout(layout)

        # Группируем фильтры в QGroupBox
        filters_group = QtWidgets.QGroupBox("Фильтры")
        filters_layout = QtWidgets.QFormLayout()
        filters_group.setLayout(filters_layout)

        # Время от / до
        self.from_datetime = QtWidgets.QDateTimeEdit()
        self.from_datetime.setCalendarPopup(True)
        self.from_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")

        self.to_datetime = QtWidgets.QDateTimeEdit()
        self.to_datetime.setCalendarPopup(True)
        self.to_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")

        today = QtCore.QDate.currentDate()
        month_ago_date = today.addMonths(-1)

        self.to_datetime.setDateTime(QtCore.QDateTime(today, QtCore.QTime(23, 59, 59)))
        self.from_datetime.setDateTime(QtCore.QDateTime(month_ago_date, QtCore.QTime(0, 0, 0)))

        filters_layout.addRow("Время от:", self.from_datetime)
        filters_layout.addRow("Время до:", self.to_datetime)

        # Тип события
        self.type_combo = QtWidgets.QComboBox()
        self.type_combo.addItem("Любой")
        filters_layout.addRow("Тип события:", self.type_combo)

        # Пользователь
        self.user_combo = QtWidgets.QComboBox()
        self.user_combo.addItem("Любой")
        # дальше мы будем подгружать список из БД, пока пусто
        filters_layout.addRow("Пользователь:", self.user_combo)

        # Статус успеха
        self.success_combo = QtWidgets.QComboBox()
        self.success_combo.addItems(["Любой", "Только успешные", "Только с ошибкой"])
        filters_layout.addRow("Статус:", self.success_combo)

        # Ключ правила
        self.key_edit = QtWidgets.QLineEdit()
        filters_layout.addRow("Ключ правила (key):", self.key_edit)

        # Общий поиск
        self.search_edit = QtWidgets.QLineEdit()
        filters_layout.addRow("Поиск по тексту:", self.search_edit)

        layout.addWidget(filters_group)

        # Кнопки применения/сброса
        buttons_layout = QtWidgets.QHBoxLayout()
        self.apply_filter_btn = QtWidgets.QPushButton("Применить")
        self.reset_filter_btn = QtWidgets.QPushButton("Сбросить")

        buttons_layout.addWidget(self.apply_filter_btn)
        buttons_layout.addWidget(self.reset_filter_btn)

        layout.addLayout(buttons_layout)

        # Растяжка, чтобы при увеличении окна фильтры не растягивались
        layout.addStretch()

        self.apply_filter_btn.clicked.connect(self._apply_filters)
        self.reset_filter_btn.clicked.connect(self._reset_filters)

        return panel

    def _update_time_filters_from_events(self):
        """
        Обновляет поля 'Время от' и 'Время до' по минимальному и максимальному timestamp
        в self.all_events. Если timestamp'ов нет — ничего не трогаем.
        """
        timestamps = [ev.get("timestamp") for ev in self.all_events if ev.get("timestamp") is not None]
        if not timestamps:
            return

        min_ts = min(timestamps)
        max_ts = max(timestamps)

        from_dt = QtCore.QDateTime.fromSecsSinceEpoch(int(min_ts))
        to_dt = QtCore.QDateTime.fromSecsSinceEpoch(int(max_ts))

        # немного расширим верхнюю границу на всякий случай (чтоб включало последнюю секунду)
        to_dt = to_dt.addSecs(1)

        # выставляем значения в виджеты
        self.from_datetime.blockSignals(True)
        self.to_datetime.blockSignals(True)
        self.from_datetime.setDateTime(from_dt)
        self.to_datetime.setDateTime(to_dt)
        self.from_datetime.blockSignals(False)
        self.to_datetime.blockSignals(False)

    def _apply_filters(self):
        """Применяет фильтры слева к self.all_events и обновляет таблицу."""
        if not self.all_events:
            # даже если пусто — обновим вид, чтобы показался плейсхолдер
            self._update_events_view([])
            return

        # --- время ---
        from_dt = self.from_datetime.dateTime()
        to_dt = self.to_datetime.dateTime()

        # делаем верхнюю границу включительно: добавим 1 сек
        from_ts = from_dt.toSecsSinceEpoch()
        to_ts = to_dt.toSecsSinceEpoch()

        type_filter = self.type_combo.currentText()
        user_filter = self.user_combo.currentText()
        success_filter = self.success_combo.currentText()
        key_filter = self.key_edit.text().strip().lower()
        text_filter = self.search_edit.text().strip().lower()

        filtered = []

        for ev in self.all_events:
            # --- фильтр по времени ---
            ts = ev.get("timestamp")
            if ts is not None:
                # timestamp у нас в float секундах
                if ts < from_ts or ts > to_ts:
                    continue
            # если ts None — можно либо пропускать, либо оставлять; оставим

            # --- тип события ---
            if type_filter != "Любой" and ev.get("event_type") != type_filter:
                continue

            # --- пользователь ---
            if user_filter != "Любой" and ev.get("user") != user_filter:
                continue

            # --- статус успеха ---
            success_val = ev.get("success", True)
            if success_filter == "Только успешные" and not success_val:
                continue
            if success_filter == "Только с ошибкой" and success_val:
                continue

            # --- ключ правила ---
            if key_filter:
                ev_key = (ev.get("key") or "").lower()
                if key_filter not in ev_key:
                    continue

            # --- общий текстовый поиск ---
            if text_filter:
                haystack = " ".join([
                    ev.get("comm", ""),
                    ev.get("exe", ""),
                    ev.get("raw", ""),
                ]).lower()
                if text_filter not in haystack:
                    continue

            filtered.append(ev)

        self._update_events_view(filtered)
        self.statusBar().showMessage(
            f"Фильтр: показано {len(filtered)} из {len(self.all_events)} событий"
        )

    def _reset_filters(self):
        """Сбрасывает фильтры в исходное состояние и показывает все события."""
        if not self.all_events:
            return

        self._update_time_filters_from_events()
        self.type_combo.setCurrentIndex(0)
        self.user_combo.setCurrentIndex(0)
        self.success_combo.setCurrentIndex(0)
        self.key_edit.clear()
        self.search_edit.clear()

        self._apply_filters()

    def _create_event_details_widget(self) -> QtWidgets.QWidget:
        """Создаёт виджет панели деталей события."""
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        widget.setLayout(layout)

        # Вкладки: Структура / Сырой лог
        tabs = QtWidgets.QTabWidget()

        # Вкладка "Структура"
        structured_tab = QtWidgets.QWidget()
        structured_layout = QtWidgets.QVBoxLayout()
        structured_tab.setLayout(structured_layout)

        # Пока просто таблица "поле = значение"
        self.details_table = QtWidgets.QTableWidget()
        self.details_table.setColumnCount(2)
        self.details_table.setHorizontalHeaderLabels(["Поле", "Значение"])
        self.details_table.horizontalHeader().setStretchLastSection(True)

        structured_layout.addWidget(self.details_table)

        # Вкладка "Сырой лог"
        raw_tab = QtWidgets.QWidget()
        raw_layout = QtWidgets.QVBoxLayout()
        raw_tab.setLayout(raw_layout)

        self.raw_text_edit = QtWidgets.QPlainTextEdit()
        self.raw_text_edit.setReadOnly(True)
        raw_layout.addWidget(self.raw_text_edit)

        tabs.addTab(structured_tab, "Структура")
        tabs.addTab(raw_tab, "Сырой лог")

        layout.addWidget(tabs)

        return widget

    def _update_events_view(self, events):
        """Обновляет таблицу событий новым списком events (уже отфильтрованных)."""
        self.events_model = AuditEventsTableModel(events, self)
        self.events_table.setModel(self.events_model)

        header = self.events_table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        # переподключаем selectionModel к нашему слоту
        selection_model = self.events_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_event_selection_changed)

        # очищаем детали
        self._clear_event_details()

    def _on_event_selection_changed(self, selected, deselected):
        """Обновляет панель деталей при выборе строки в таблице."""
        indexes = selected.indexes()
        if not indexes:
            # ничего не выбрано — очищаем детали
            self._clear_event_details()
            return

        # Берём первую выбранную ячейку и узнаём номер строки
        row = indexes[0].row()

        event = self.events_model.get_event(row)
        if not event:
            self._clear_event_details()
            return

        # Заполняем таблицу деталей
        details = event.get("details", {})
        self.details_table.setRowCount(len(details))

        for i, (field, value) in enumerate(details.items()):
            field_item = QtWidgets.QTableWidgetItem(str(field))
            value_item = QtWidgets.QTableWidgetItem(str(value))
            self.details_table.setItem(i, 0, field_item)
            self.details_table.setItem(i, 1, value_item)

        # Обновляем сырой лог
        raw_text = event.get("raw", "")
        self.raw_text_edit.setPlainText(raw_text)

    def _clear_event_details(self):
        """Очищает панель деталей."""
        self.details_table.setRowCount(0)
        self.raw_text_edit.clear()
