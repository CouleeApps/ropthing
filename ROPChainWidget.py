from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, \
    QHeaderView, QAbstractItemView

import re
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler
from binaryninja import BinaryView

from .model import ROPChain, format_addr


class ROPChainListModel(QAbstractItemModel):
    def __init__(self, parent, bv: BinaryView, state: ROPChain):
        QAbstractItemModel.__init__(self, parent)
        self.bv = bv
        self.columns = ["Offset", "Gadget", "Code"]
        self.state = state
        self.rows = []
        self.update_rows()

    def setState(self, state: ROPChain):
        self.state = state
        self.state.add_listener(lambda i, v: self.update_rows())
        self.update_rows()

    def update_rows(self):
        self.beginResetModel()

        self.rows = []
        if self.state is None:
            self.endResetModel()
            return

        # Fill self.rows
        for i, addr in reversed(list(enumerate(self.state.chain))):
            self.rows.append([i, addr, format_addr(self.bv, addr)])

        self.endResetModel()
        self.dataChanged.emit(self.index(0, 0, QModelIndex()), self.index(len(self.rows) - 1, len(self.columns) - 1, QModelIndex()), [Qt.DisplayRole])
        self.layoutChanged.emit()

    def index(self, row, column, parent):
        if parent.isValid() or column > len(self.columns) or row >= len(self.rows):
            return QModelIndex()
        return self.createIndex(row, column)

    def parent(self, child):
        return QModelIndex()

    def hasChildren(self, parent):
        return False

    def rowCount(self, parent):
        if parent.isValid():
            return 0
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.columns)

    def flags(self, index):
        f = super().flags(index)
        if index.column() == 1:
            f |= Qt.ItemIsEditable
        return f

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Vertical:
            return None
        return self.columns[section]

    def data(self, index, role):
        if not index.isValid():
            return None
        if index.row() < 0 or index.row() >= len(self.rows):
            return None

        conts = self.rows[index.row()][index.column()]

        if role == Qt.DisplayRole:
            # Format data into displayable text
            if self.columns[index.column()] == "Gadget":
                text = ('%x' % conts).rjust(self.bv.arch.address_size * 2, "0")
            elif self.columns[index.column()] == "Offset":
                offset = (len(self.state.chain) - conts - 1) * 4
                text = ('%x' % offset)
            else:
                text = str(conts)
            return text

        return None

    def setData(self, index, value, role):
        # Verify that we can edit this value
        if (self.flags(index) & Qt.EditRole) != Qt.EditRole:
            return False
        if len(value) == 0:
            return False

        old_row = self.rows[index.row()]
        old_val = old_row[1]
        try:
            new_val = int(value, 16)
        except:
            return False

        if new_val == old_val:
            return False

        self.bv.begin_undo_actions()
        self.state[old_row[0]] = new_val
        self.state.update_segment()
        self.bv.commit_undo_actions()
        self.bv.navigate(f"Graph:{self.bv.view_type}", self.state.address_at_index(old_row[0]))

        self.rows[index.row()] = [old_row[0], new_val, format_addr(self.bv, new_val)]
        self.dataChanged.emit(index, index, [role])
        self.layoutChanged.emit()
        return True


class ROPChainItemDelegate(QItemDelegate):
    def __init__(self, parent):
        QItemDelegate.__init__(self, parent)

        self.font = binaryninjaui.getMonospaceFont(parent)
        self.font.setKerning(False)
        self.baseline = QFontMetricsF(self.font).ascent()
        self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
        self.char_height = QFontMetricsF(self.font).height()
        self.char_offset = binaryninjaui.getFontVerticalOffset()

        self.expected_char_widths = [5, 10, 32]

    def sizeHint(self, option, idx):
        width = self.expected_char_widths[idx.column()]
        data = idx.data()
        if data is not None:
            width = max(width, len(data))
        return QSize(self.char_width * width + 4, self.char_height)

    def paint(self, painter, option, idx):
        # Draw background highlight in theme style
        selected = option.state & QStyle.State_Selected != 0
        if selected:
            painter.setBrush(binaryninjaui.getThemeColor(binaryninjaui.SelectionColor))
        else:
            painter.setBrush(option.backgroundBrush)
        painter.setPen(Qt.NoPen)
        painter.drawRect(option.rect)

        text = idx.data()

        # Draw text depending on state
        painter.setFont(self.font)
        painter.setPen(option.palette.color(QPalette.WindowText).rgba())
        painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))

    def setEditorData(self, editor, idx):
        if idx.column() == 1:
            data = idx.data()
            editor.setText(data)


class ROPChainWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        if not type(data) == BinaryView:
            raise Exception('expected widget data to be a BinaryView')

        self.bv = data

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.table = QTableView(self)
        self.state = None
        self.model = ROPChainListModel(self.table, data, None)
        self.table.setModel(self.model)

        self.item_delegate = ROPChainItemDelegate(self)
        self.table.setItemDelegate(self.item_delegate)

        # self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)

        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

        for i in range(len(self.model.columns)):
            self.table.setColumnWidth(i, self.item_delegate.sizeHint(self.table.viewOptions(),
                                                                     self.model.index(-1, i, QModelIndex())).width())

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.table)
        self.setLayout(layout)

    def notifyOffsetChanged(self, offset):
        pass

    def setState(self, state: ROPChain):
        self.state = state
        self.model.setState(state)
        self.table.resizeColumnsToContents()

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

