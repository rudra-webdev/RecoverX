"""
File Table Model for RecoverX GUI
QAbstractTableModel providing progressive row insertion, checkbox selection,
fast filtering, column sorting, and metadata inspection.
"""
from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex, Signal
from typing import List, Dict, Any, Optional

class FileItemEntry:
    def __init__(self, raw_data: Dict[str, Any]):
        self.raw = raw_data
        self.selected = False
        self.offset = raw_data.get("offset", 0)
        self.filename = raw_data.get("filename", f"carved_{self.offset:08x}.{raw_data.get('extension', 'bin')}")
        self.extension = raw_data.get("extension", "unknown").upper()
        self.category = raw_data.get("category", "Other")
        self.original_path = raw_data.get("original_path") or f"Sector 0x{self.offset:08X}"
        self.size_bytes = raw_data.get("length", raw_data.get("size_bytes", 0))
        self.is_valid = raw_data.get("is_valid", False)
        self.confidence = raw_data.get("confidence", 0.0)
        self.is_duplicate = raw_data.get("is_duplicate", False)
        self.fragmented = raw_data.get("fragmented_warning", False)
        self.sha256 = raw_data.get("sha256", "")
        self.backend = raw_data.get("backend", "RecoverX Carver")

    @property
    def status_string(self) -> str:
        if self.is_duplicate:
            return "Duplicate (Skip)"
        if self.is_valid and not self.fragmented:
            return "Recoverable"
        if self.fragmented or (self.is_valid and self.confidence < 0.7):
            return "Partially Recoverable"
        return "Invalid / Incomplete"

    @property
    def formatted_size(self) -> str:
        if self.size_bytes < 1024:
            return f"{self.size_bytes} B"
        elif self.size_bytes < 1024 * 1024:
            return f"{self.size_bytes / 1024:.1f} KB"
        elif self.size_bytes < 1024 * 1024 * 1024:
            return f"{self.size_bytes / (1024 * 1024):.2f} MB"
        return f"{self.size_bytes / (1024 * 1024 * 1024):.2f} GB"

class FileTableModel(QAbstractTableModel):
    selection_changed = Signal(int)  # Emits current number of selected items

    COLUMNS = [
        "",                      # Checkbox (col 0)
        "Filename",              # Col 1
        "Type",                  # Col 2
        "Category",              # Col 3
        "Original Path / Source",# Col 4
        "Size",                  # Col 5
        "Recovery Status",       # Col 6
        "Confidence",            # Col 7
        "SHA-256",               # Col 8
        "Engine"                 # Col 9
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_items: List[FileItemEntry] = []
        self._filtered_items: List[FileItemEntry] = []
        self.active_category: str = "All"
        self.active_status: str = "All"
        self.search_query: str = ""
        self._sort_column: int = 1
        self._sort_order: Qt.SortOrder = Qt.SortOrder.AscendingOrder

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._filtered_items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._filtered_items):
            return None

        item = self._filtered_items[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.CheckStateRole and col == 0:
            return Qt.CheckState.Checked if item.selected else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1:
                return item.filename
            elif col == 2:
                return item.extension
            elif col == 3:
                return item.category
            elif col == 4:
                return item.original_path
            elif col == 5:
                return item.formatted_size
            elif col == 6:
                return item.status_string
            elif col == 7:
                return f"{int(item.confidence * 100)}%"
            elif col == 8:
                return item.sha256[:12] + "..." if item.sha256 else "N/A"
            elif col == 9:
                return item.backend

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 2, 5, 7):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        return None

    def setData(self, index: QModelIndex, value: Any, role=Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid() or index.row() >= len(self._filtered_items):
            return False

        if index.column() == 0 and role == Qt.ItemDataRole.CheckStateRole:
            item = self._filtered_items[index.row()]
            item.selected = (value == Qt.CheckState.Checked.value or value is True)
            self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
            self.selection_changed.emit(len(self.get_selected_items()))
            return True

        return False

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        base_flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            return base_flags | Qt.ItemFlag.ItemIsUserCheckable
        return base_flags

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self.COLUMNS):
                return self.COLUMNS[section]
        return None

    def add_item(self, raw_item: Dict[str, Any]):
        """Progressively adds a discovered or carved item to the table."""
        entry = FileItemEntry(raw_item)
        self._all_items.append(entry)

        if self._matches_filter(entry):
            row = len(self._filtered_items)
            self.beginInsertRows(QModelIndex(), row, row)
            self._filtered_items.append(entry)
            self.endInsertRows()

    def set_items(self, items: List[Dict[str, Any]]):
        """Replaces all items in table."""
        self.beginResetModel()
        self._all_items = [FileItemEntry(i) for i in items]
        self._filtered_items = [i for i in self._all_items if self._matches_filter(i)]
        self._apply_sort()
        self.endResetModel()
        self.selection_changed.emit(len(self.get_selected_items()))

    def clear(self):
        self.beginResetModel()
        self._all_items.clear()
        self._filtered_items.clear()
        self.endResetModel()
        self.selection_changed.emit(0)

    def set_filter(self, category: Optional[str] = None, status: Optional[str] = None, search: Optional[str] = None):
        if category is not None:
            self.active_category = category
        if status is not None:
            self.active_status = status
        if search is not None:
            self.search_query = search.lower().strip()

        self.beginResetModel()
        self._filtered_items = [i for i in self._all_items if self._matches_filter(i)]
        self._apply_sort()
        self.endResetModel()
        self.selection_changed.emit(len(self.get_selected_items()))

    def _matches_filter(self, entry: FileItemEntry) -> bool:
        if self.active_category != "All" and entry.category != self.active_category:
            return False

        if self.active_status != "All":
            if self.active_status == "Recoverable" and entry.status_string != "Recoverable":
                return False
            if self.active_status == "Partially recoverable" and entry.status_string != "Partially Recoverable":
                return False
            if self.active_status == "Invalid or incomplete" and entry.status_string != "Invalid / Incomplete":
                return False

        if self.search_query:
            query = self.search_query
            if query not in entry.filename.lower() and query not in entry.extension.lower() and query not in entry.original_path.lower():
                return False

        return True

    def select_all(self, select: bool = True):
        self.beginResetModel()
        for item in self._filtered_items:
            item.selected = select
        self.endResetModel()
        self.selection_changed.emit(len(self.get_selected_items()))

    def get_selected_items(self) -> List[FileItemEntry]:
        return [item for item in self._filtered_items if item.selected]

    def get_item(self, row: int) -> Optional[FileItemEntry]:
        if 0 <= row < len(self._filtered_items):
            return self._filtered_items[row]
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder):
        """Sorts the table data by the chosen column."""
        self._sort_column = column
        self._sort_order = order
        self.beginResetModel()
        self._apply_sort()
        self.endResetModel()

    def _apply_sort(self):
        reverse = (self._sort_order == Qt.SortOrder.DescendingOrder)
        col = self._sort_column

        if col == 1:
            self._filtered_items.sort(key=lambda x: x.filename.lower(), reverse=reverse)
        elif col == 2:
            self._filtered_items.sort(key=lambda x: x.extension.lower(), reverse=reverse)
        elif col == 3:
            self._filtered_items.sort(key=lambda x: x.category.lower(), reverse=reverse)
        elif col == 4:
            self._filtered_items.sort(key=lambda x: x.offset, reverse=reverse)
        elif col == 5:
            self._filtered_items.sort(key=lambda x: x.size_bytes, reverse=reverse)
        elif col == 6:
            self._filtered_items.sort(key=lambda x: x.status_string, reverse=reverse)
        elif col == 7:
            self._filtered_items.sort(key=lambda x: x.confidence, reverse=reverse)
        elif col == 8:
            self._filtered_items.sort(key=lambda x: x.sha256, reverse=reverse)
        elif col == 9:
            self._filtered_items.sort(key=lambda x: x.backend.lower(), reverse=reverse)
