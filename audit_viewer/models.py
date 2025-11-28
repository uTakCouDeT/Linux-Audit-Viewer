from PyQt5 import QtCore, QtWidgets, QtGui


class PlaceholderTableView(QtWidgets.QTableView):
    """QTableView, которая показывает текст, когда нет данных."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_events = []  # сюда будем класть все загруженные события
        self._placeholder_text = ""

    def setPlaceholderText(self, text: str):
        self._placeholder_text = text
        self.viewport().update()

    def paintEvent(self, event):
        super().paintEvent(event)

        model = self.model()
        if not self._placeholder_text:
            return
        if model and model.rowCount() > 0:
            return

        painter = QtGui.QPainter(self.viewport())
        painter.setRenderHint(QtGui.QPainter.TextAntialiasing)

        # тусклый цвет текста
        palette = self.palette()
        color = palette.color(QtGui.QPalette.Disabled, QtGui.QPalette.Text)
        painter.setPen(color)

        rect = self.viewport().rect()
        painter.drawText(rect, QtCore.Qt.AlignCenter, self._placeholder_text)


class AuditEventsTableModel(QtCore.QAbstractTableModel):
    """Модель для таблицы событий auditd."""

    COLUMNS = [
        "time",  # Время
        "user",  # Пользователь
        "event_type",  # Тип события
        "comm",  # Команда
        "exe",  # Исполняемый файл
        "success",  # Успех/ошибка
        "key",  # Ключ правила
    ]

    HEADERS = [
        "Время",
        "Пользователь",
        "Тип",
        "Команда",
        "Исполняемый файл",
        "Успех",
        "Ключ",
    ]

    def __init__(self, events=None, parent=None):
        super().__init__(parent)
        self._events = events or []

    # Обязательные методы модели:

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self.COLUMNS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None

        if role == QtCore.Qt.DisplayRole:
            event = self._events[index.row()]
            col_key = self.COLUMNS[index.column()]
            value = event.get(col_key, "")
            # Приводим bool success к "yes"/"no" для красоты
            if col_key == "success":
                return "yes" if value else "no"
            return str(value)

        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        # Заголовки колонок
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return super().headerData(section, orientation, role)

    # Удобный метод, чтобы забирать целое событие по номеру строки
    def get_event(self, row: int) -> dict:
        if 0 <= row < len(self._events):
            return self._events[row]
        return {}

    def sort(self, column, order=QtCore.Qt.AscendingOrder):
        """Сортировка данных по выбранной колонке."""
        if not (0 <= column < len(self.COLUMNS)):
            return

        col_key = self.COLUMNS[column]
        reverse = (order == QtCore.Qt.DescendingOrder)

        # уведомляем представление, что сейчас будет перестановка
        self.layoutAboutToBeChanged.emit()

        # для времени лучше сортировать по timestamp, если он есть
        if col_key == "time":
            def key_func(ev):
                ts = ev.get("timestamp")
                if ts is None:
                    return 0
                return ts
        else:
            def key_func(ev):
                val = ev.get(col_key)
                if val is None:
                    return ""
                return str(val)

        self._events.sort(key=key_func, reverse=reverse)

        # сообщаем, что данные переставлены
        self.layoutChanged.emit()
