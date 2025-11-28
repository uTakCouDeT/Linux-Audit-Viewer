from PyQt5 import QtWidgets, QtCore
from datetime import datetime

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from .incidents import find_critical_file_changes


class StatsTabMixin:
    """Методы, относящиеся к вкладке 'Статистика'."""

    def _init_stats_tab(self):
        """Вкладка 'Статистика': фильтр по времени + агрегаты + таблицы."""
        # Главный layout вкладки
        main_layout = QtWidgets.QVBoxLayout()
        self.stats_tab.setLayout(main_layout)

        # Прокручиваемая область
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        main_layout.addWidget(scroll_area)

        # Внутренний контейнер для всего содержимого
        container = QtWidgets.QWidget()
        scroll_area.setWidget(container)

        layout = QtWidgets.QVBoxLayout()
        container.setLayout(layout)

        # --- Фильтры по времени ---
        filters_group = QtWidgets.QGroupBox("Фильтры")
        filters_layout = QtWidgets.QHBoxLayout()
        filters_group.setLayout(filters_layout)

        self.stats_from_datetime = QtWidgets.QDateTimeEdit()
        self.stats_from_datetime.setCalendarPopup(True)
        self.stats_from_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")

        self.stats_to_datetime = QtWidgets.QDateTimeEdit()
        self.stats_to_datetime.setCalendarPopup(True)
        self.stats_to_datetime.setDisplayFormat("yyyy-MM-dd HH:mm:ss")

        filters_layout.addWidget(QtWidgets.QLabel("Время от:"))
        filters_layout.addWidget(self.stats_from_datetime)
        filters_layout.addWidget(QtWidgets.QLabel("Время до:"))
        filters_layout.addWidget(self.stats_to_datetime)

        self.stats_apply_btn = QtWidgets.QPushButton("Применить")
        self.stats_reset_btn = QtWidgets.QPushButton("Сбросить")

        filters_layout.addWidget(self.stats_apply_btn)
        filters_layout.addWidget(self.stats_reset_btn)
        filters_layout.addStretch()

        # Пока нет данных — отключаем
        self.stats_from_datetime.setEnabled(False)
        self.stats_to_datetime.setEnabled(False)
        self.stats_apply_btn.setEnabled(False)
        self.stats_reset_btn.setEnabled(False)

        self.stats_apply_btn.clicked.connect(self._recalculate_stats)
        self.stats_reset_btn.clicked.connect(self._reset_stats_filters)

        layout.addWidget(filters_group)

        # --- Общая статистика (цифры) ---
        summary_group = QtWidgets.QGroupBox("Общая статистика")
        summary_layout = QtWidgets.QFormLayout()
        summary_group.setLayout(summary_layout)

        self.stats_total_events_label = QtWidgets.QLabel("0")
        self.stats_unique_users_label = QtWidgets.QLabel("0")
        self.stats_unique_types_label = QtWidgets.QLabel("0")
        self.stats_failed_auth_label = QtWidgets.QLabel("0")
        self.stats_critical_changes_label = QtWidgets.QLabel("0")

        summary_layout.addRow("Всего событий в периоде:", self.stats_total_events_label)
        summary_layout.addRow("Уникальных пользователей:", self.stats_unique_users_label)
        summary_layout.addRow("Уникальных типов событий:", self.stats_unique_types_label)
        summary_layout.addRow("Неуспешных аутентификаций:", self.stats_failed_auth_label)
        summary_layout.addRow("Изменений критичных файлов:", self.stats_critical_changes_label)

        layout.addWidget(summary_group)

        # --- Таблица + график: события по типам ---
        types_group = QtWidgets.QGroupBox("Распределение событий по типам")
        types_layout = QtWidgets.QHBoxLayout()
        types_group.setLayout(types_layout)

        self.stats_types_table = QtWidgets.QTableWidget()
        self.stats_types_table.setColumnCount(2)
        self.stats_types_table.setHorizontalHeaderLabels(["Тип события", "Количество"])
        self.stats_types_table.horizontalHeader().setStretchLastSection(True)
        self.stats_types_table.setMinimumHeight(400)  # побольше по высоте

        # Канвас для графика по типам
        self.stats_types_figure = plt.Figure(figsize=(4, 2))
        self.stats_types_canvas = FigureCanvas(self.stats_types_figure)

        types_layout.addWidget(self.stats_types_table, 2)
        types_layout.addWidget(self.stats_types_canvas, 3)

        layout.addWidget(types_group)

        # --- Таблица + график: события по пользователям ---
        users_group = QtWidgets.QGroupBox("Распределение событий по пользователям")
        users_layout = QtWidgets.QHBoxLayout()
        users_group.setLayout(users_layout)

        self.stats_users_table = QtWidgets.QTableWidget()
        self.stats_users_table.setColumnCount(2)
        self.stats_users_table.setHorizontalHeaderLabels(["Пользователь", "Количество"])
        self.stats_users_table.horizontalHeader().setStretchLastSection(True)
        self.stats_users_table.setMinimumHeight(400)

        self.stats_users_figure = plt.Figure(figsize=(4, 2))
        self.stats_users_canvas = FigureCanvas(self.stats_users_figure)

        users_layout.addWidget(self.stats_users_table, 2)
        users_layout.addWidget(self.stats_users_canvas, 3)

        layout.addWidget(users_group)

        # --- Таблица + график: события по дням ---
        days_group = QtWidgets.QGroupBox("Распределение событий по дням")
        days_layout = QtWidgets.QHBoxLayout()
        days_group.setLayout(days_layout)

        self.stats_days_table = QtWidgets.QTableWidget()
        self.stats_days_table.setColumnCount(2)
        self.stats_days_table.setHorizontalHeaderLabels(["Дата", "Количество событий"])
        self.stats_days_table.horizontalHeader().setStretchLastSection(True)
        self.stats_days_table.setMinimumHeight(400)

        self.stats_days_figure = plt.Figure(figsize=(4, 2))
        self.stats_days_canvas = FigureCanvas(self.stats_days_figure)

        days_layout.addWidget(self.stats_days_table, 2)
        days_layout.addWidget(self.stats_days_canvas, 3)

        layout.addWidget(days_group)

        types_group.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        users_group.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        days_group.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)

    def _get_stats_filtered_events(self):
        """Возвращает список событий, попадающих в диапазон на вкладке 'Статистика'."""
        if not self.all_events:
            return []

        # если виджеты ещё не инициализированы или выключены
        if not hasattr(self, "stats_from_datetime"):
            return self.all_events

        from_dt = self.stats_from_datetime.dateTime()
        to_dt = self.stats_to_datetime.dateTime()

        from_ts = from_dt.toSecsSinceEpoch()
        to_ts = to_dt.toSecsSinceEpoch()

        result = []
        for ev in self.all_events:
            ts = ev.get("timestamp")
            if ts is None:
                # если вдруг нет таймстемпа — можно либо включать, либо пропускать; включим
                result.append(ev)
                continue
            if from_ts <= ts <= to_ts:
                result.append(ev)

        return result

    def _update_stats_time_filters_from_events(self):
        """Выставляет 'Время от/до' на вкладке 'Статистика' по min/max timestamp в all_events."""
        timestamps = [ev.get("timestamp") for ev in self.all_events if ev.get("timestamp") is not None]
        if not timestamps:
            return

        min_ts = min(timestamps)
        max_ts = max(timestamps)

        from_dt = QtCore.QDateTime.fromSecsSinceEpoch(int(min_ts))
        to_dt = QtCore.QDateTime.fromSecsSinceEpoch(int(max_ts))
        to_dt = to_dt.addSecs(1)

        self.stats_from_datetime.blockSignals(True)
        self.stats_to_datetime.blockSignals(True)
        self.stats_from_datetime.setDateTime(from_dt)
        self.stats_to_datetime.setDateTime(to_dt)
        self.stats_from_datetime.blockSignals(False)
        self.stats_to_datetime.blockSignals(False)

    def _update_stats_controls_state(self):
        """Включает/выключает элементы управления на вкладке 'Статистика' в зависимости от наличия данных."""
        has_events = bool(self.all_events)
        if not hasattr(self, "stats_from_datetime"):
            return

        self.stats_from_datetime.setEnabled(has_events)
        self.stats_to_datetime.setEnabled(has_events)
        self.stats_apply_btn.setEnabled(has_events)
        self.stats_reset_btn.setEnabled(has_events)

        if not has_events:
            # очищаем таблицы и цифры
            self.stats_total_events_label.setText("0")
            self.stats_unique_users_label.setText("0")
            self.stats_unique_types_label.setText("0")
            self.stats_failed_auth_label.setText("0")
            self.stats_critical_changes_label.setText("0")

            self.stats_types_table.setRowCount(0)
            self.stats_users_table.setRowCount(0)
            self.stats_days_table.setRowCount(0)

            if hasattr(self, "stats_types_figure"):
                self._update_bar_chart(self.stats_types_figure, self.stats_types_canvas, [], [],
                                       title="События по типам")
                self._update_bar_chart(self.stats_users_figure, self.stats_users_canvas, [], [],
                                       title="События по пользователям")
                self._update_bar_chart(self.stats_days_figure, self.stats_days_canvas, [], [], title="События по дням",
                                       line=True)

    def _recalculate_stats(self):
        """Пересчитывает статистику на основе текущих событий и временного диапазона."""
        if not self.all_events:
            self._update_stats_controls_state()
            return

        events = self._get_stats_filtered_events()

        total = len(events)
        users_set = {ev.get("user") for ev in events if ev.get("user")}
        types_set = {ev.get("event_type") for ev in events if ev.get("event_type")}

        # неуспешные аутентификации
        failed_auth = 0
        for ev in events:
            etype = ev.get("event_type")
            if etype in ("USER_AUTH", "USER_LOGIN") and not ev.get("success", True):
                failed_auth += 1

        # критичные изменения
        critical_changes = len(find_critical_file_changes(events))

        # Заполняем цифры
        self.stats_total_events_label.setText(str(total))
        self.stats_unique_users_label.setText(str(len(users_set)))
        self.stats_unique_types_label.setText(str(len(types_set)))
        self.stats_failed_auth_label.setText(str(failed_auth))
        self.stats_critical_changes_label.setText(str(critical_changes))

        # --- Таблица по типам ---
        type_counts = {}
        for ev in events:
            t = ev.get("event_type") or "UNKNOWN"
            type_counts[t] = type_counts.get(t, 0) + 1

        self.stats_types_table.setRowCount(len(type_counts))
        for row, (t, cnt) in enumerate(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)):
            self.stats_types_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(t)))
            self.stats_types_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(cnt)))

        # График по типам
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        type_labels = [str(t) for t, _ in sorted_types]
        type_values = [cnt for _, cnt in sorted_types]
        self._update_bar_chart(
            self.stats_types_figure,
            self.stats_types_canvas,
            type_labels,
            type_values,
            title="События по типам",
            horizontal=True,
            line=False,
        )

        # --- Таблица по пользователям ---
        user_counts = {}
        for ev in events:
            u = ev.get("user") or "?"
            user_counts[u] = user_counts.get(u, 0) + 1

        self.stats_users_table.setRowCount(len(user_counts))
        for row, (u, cnt) in enumerate(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)):
            self.stats_users_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(u)))
            self.stats_users_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(cnt)))

        # График по пользователям
        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
        user_labels = [str(u) for u, _ in sorted_users]
        user_values = [cnt for _, cnt in sorted_users]
        self._update_bar_chart(
            self.stats_users_figure,
            self.stats_users_canvas,
            user_labels,
            user_values,
            title="События по пользователям",
            horizontal=True,
            line=False,
        )

        # --- Таблица по дням ---
        day_counts = {}
        for ev in events:
            ts = ev.get("timestamp")
            if ts is None:
                continue
            dt = datetime.fromtimestamp(ts)
            day_str = dt.strftime("%Y-%m-%d")
            day_counts[day_str] = day_counts.get(day_str, 0) + 1

        self.stats_days_table.setRowCount(len(day_counts))
        for row, (day, cnt) in enumerate(sorted(day_counts.items())):
            self.stats_days_table.setItem(row, 0, QtWidgets.QTableWidgetItem(day))
            self.stats_days_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(cnt)))

        # График по дням
        sorted_days = sorted(day_counts.items())
        day_labels = [day for day, _ in sorted_days]
        day_values = [cnt for _, cnt in sorted_days]
        self._update_bar_chart(
            self.stats_days_figure,
            self.stats_days_canvas,
            day_labels,
            day_values,
            title="События по дням",
            horizontal=False,
            line=True,
        )

    def _reset_stats_filters(self):
        """Сбрасывает фильтры на вкладке 'Статистика' к min/max по журналу и пересчитывает статистику."""
        if not self.all_events:
            return
        self._update_stats_time_filters_from_events()
        self._recalculate_stats()

    def _update_bar_chart(self, figure, canvas, labels, values, title="", horizontal=False, line=False):
        """
        Обновляет график на заданном FigureCanvas.
        - horizontal=True  -> горизонтальная гистограмма
        - line=True        -> линейный график
        """
        ax = figure.gca()
        ax.clear()

        if not labels or not values:
            ax.set_title(title)
            ax.set_xticks([])
            ax.set_yticks([])
            canvas.draw()
            return

        max_points = 15  # не перегружать график
        labels = labels[:max_points]
        values = values[:max_points]

        if line:
            x = range(len(labels))
            ax.plot(x, values, marker="o")
            ax.set_xticks(x)
            ax.set_xticklabels(labels, rotation=45, ha="right")
        else:
            if horizontal:
                y = range(len(labels))
                ax.barh(y, values)
                ax.set_yticks(y)
                ax.set_yticklabels(labels)
                ax.invert_yaxis()  # самая большая сверху
            else:
                x = range(len(labels))
                ax.bar(x, values)
                ax.set_xticks(x)
                ax.set_xticklabels(labels, rotation=45, ha="right")

        ax.set_title(title)
        ax.margins(x=0.05)
        figure.tight_layout()
        canvas.draw()
