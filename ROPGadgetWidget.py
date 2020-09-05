import functools
import threading
import time

from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF, QKeyEvent, QClipboard
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, \
    QHeaderView, QAbstractItemView

import re
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler, FilterTarget, FilteredView, UIContext, ViewFrame, \
    UIAction
from binaryninja import BinaryView, BackgroundTaskThread, execute_on_main_thread_and_wait, execute_on_main_thread, \
    AnalysisState

from .model import disasm_at_addr


class ROPGadgetListModel(QAbstractItemModel):
    def __init__(self, parent, bv: BinaryView):
        QAbstractItemModel.__init__(self, parent)
        self.bv = bv
        self.columns = ["Address", "Gadget"]
        self.update_lock = threading.Lock()
        self.updating = False
        self.last_filter = ""
        self.rows = []
        self.filtered_rows = []
        self.update_rows()
        self.set_filter("")

    def update_rows(self):
        if not self.update_lock.acquire(False):
            return

        self.updating = True
        self.rows = []

        class ROPGadgetListTask(BackgroundTaskThread):
            def __init__(self, bv: BinaryView, model):
                super(ROPGadgetListTask, self).__init__("Finding Gadgets", True)
                self.bv = bv
                self.model = model

            def run(self):
                time.sleep(1)
                self.progress = "Finding Gadgets (Waiting for analysis...)"
                if self.bv.analysis_info.state == AnalysisState.IdleState:
                    self._run()
                else:
                    self.bv.add_analysis_completion_event(self._run)

            def _run(self):
                rop_addrs = {}
                found_addrs = set()
                found_rows = []
                last_progress_time = time.time()
                last_update_time = time.time()

                start = self.bv.start
                end = self.bv.end

                def update_rows():
                    nonlocal last_update_time
                    self.model.rows = found_rows
                    self.model.set_filter(self.model.last_filter)
                    last_update_time = time.time()

                matches = ['retn', 'int', 'syscall']

                def test_op(disasm):
                    for search in matches:
                        if search in disasm:
                            return True
                    return False

                for _, addr in self.bv.instructions:
                    if self.cancelled:
                        return

                    if time.time() - last_update_time > 1.0:
                        # TODO: Why is this so slow? It's just displaying text in a table...
                        execute_on_main_thread(update_rows)

                    if time.time() - last_progress_time > 0.5:
                        self.progress = f"Finding Gadgets (1/2, {100 * (addr - start) / (end - start):.2f}%)"
                        last_progress_time = time.time()

                    disasm = disasm_at_addr(self.bv, addr)
                    if test_op(disasm):
                        if disasm not in rop_addrs:
                            rop_addrs[disasm] = addr
                            found_rows.append([addr, disasm])
                    found_addrs.add(addr)

                for segment in self.bv.segments:
                    if not segment.executable:
                        continue

                    for addr in range(segment.start, segment.end):
                        if self.cancelled:
                            return

                        if addr in found_addrs:
                            continue

                        if time.time() - last_update_time > 10.0:
                            execute_on_main_thread(update_rows)

                        if time.time() - last_progress_time > 0.5:
                            self.progress = f"Finding Gadgets (2/2, {100 * (addr - start) / (end - start):.2f}%)"
                            last_progress_time = time.time()

                        disasm = disasm_at_addr(self.bv, addr)
                        if test_op(disasm):
                            if disasm not in rop_addrs:
                                rop_addrs[disasm] = addr
                                found_rows.append([addr, disasm])

                self.progress = f"Finding Gadgets (Finishing...)"
                update_rows()
                self.finish()
                self.model.updating = False

        t = ROPGadgetListTask(self.bv, self)
        t.start()

    def set_filter(self, filter):
        self.beginResetModel()
        self.last_filter = filter

        self.filtered_rows = []

        def compare_gadgets(a, b):
            starta = a[1].startswith(filter)
            startb = b[1].startswith(filter)

            if starta and not startb:
                return -1
            if startb and not starta:
                return 1

            if len(filter) > 0:
                if len(a[1]) < len(b[1]):
                    return -1
                if len(b[1]) < len(a[1]):
                    return 1
            if a[1] < b[1]:
                return -1
            if b[1] < a[1]:
                return 1
            return 0

        for row in sorted(self.rows, key=functools.cmp_to_key(compare_gadgets)):
            if filter in row[1]:
                self.filtered_rows.append(row)

        self.endResetModel()
        QWidget.parent(self).parent().setWindowTitle(f"ROP Gadgets ({len(self.filtered_rows)} / {len(self.rows)})")

    def index(self, row, column, parent):
        if parent.isValid() or column > len(self.columns) or row >= len(self.filtered_rows):
            return QModelIndex()
        return self.createIndex(row, column)

    def parent(self, child):
        return QModelIndex()

    def hasChildren(self, parent):
        return False

    def rowCount(self, parent):
        if parent.isValid():
            return 0
        return len(self.filtered_rows)

    def columnCount(self, parent):
        return len(self.columns)

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Vertical:
            return None
        return self.columns[section]

    def data(self, index, role):
        if not index.isValid():
            return None
        if index.row() < 0 or index.row() >= len(self.filtered_rows):
            return None

        conts = self.filtered_rows[index.row()][index.column()]

        if role == Qt.DisplayRole:
            # Format data into displayable text
            if self.columns[index.column()] == "Address":
                text = ('%x' % conts).rjust(self.bv.arch.address_size * 2, "0")
            else:
                text = str(conts)
            return text
        if role == Qt.UserRole:
            # Clipboard
            return ('%x' % self.filtered_rows[index.row()][0]).rjust(self.bv.arch.address_size * 2, "0")


        return None


class ROPGadgetItemDelegate(QItemDelegate):
    def __init__(self, parent, data):
        QItemDelegate.__init__(self, parent)

        self.font = binaryninjaui.getMonospaceFont(parent)
        self.font.setKerning(False)
        self.baseline = QFontMetricsF(self.font).ascent()
        self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
        self.char_height = QFontMetricsF(self.font).height()
        self.char_offset = binaryninjaui.getFontVerticalOffset()

        self.expected_char_widths = [data.arch.address_size * 2 + 2, 64]

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


class ROPGadgetList(QTableView, FilterTarget):
    def __init__(self, parent, frame, model_: ROPGadgetListModel):
        QTableView.__init__(self, parent)
        FilterTarget.__init__(self)
        self.frame = frame
        self.filter = None
        self.model_ = model_
        self.filter_view: FilteredView = None

        # self.setSortingEnabled(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.verticalHeader().setVisible(False)

        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

        self.resizeColumnsToContents()
        self.resizeRowsToContents()

        UIActionHandler.actionHandlerFromWidget(self).bindAction("Copy", UIAction(lambda e: self.copy()))

    def copy(self):
        QApplication.clipboard().setText(self.model_.data(self.currentIndex(), Qt.UserRole))

    def keyPressEvent(self, event: QKeyEvent):
        if len(event.text()) > 0 and ord(event.text()[0]) > ord(' ') and ord(event.text()[0]) != Qt.Key_Backspace:
            if self.filter_view is not None:
                self.filter_view.showFilter(event.text())
                event.accept()

        if event.key() == Qt.Key_C and event.modifiers() & Qt.ControlModifier:
            self.copy()

        QTableView.keyPressEvent(self, event)

    def setFilter(self, text):
        self.model_.set_filter(text)

    def scrollToFirstItem(self):
        self.scrollToTop()

    def scrollToCurrentItem(self):
        pass

    def selectFirstItem(self):
        self.setCurrentIndex(self.model().index(0, 0, QModelIndex()))

    def activateFirstItem(self):
        pass


class ROPGadgetWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        if not type(data) == BinaryView:
            raise Exception('expected widget data to be a BinaryView')

        self.bv = data

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.model = ROPGadgetListModel(self, data)
        self.table = ROPGadgetList(self, ViewFrame.viewFrameForWidget(parent), self.model)
        self.filter_view = FilteredView(self, self.table, self.table)
        self.table.filter_view = self.filter_view
        self.table.setModel(self.model)

        self.item_delegate = ROPGadgetItemDelegate(self, data)
        self.table.setItemDelegate(self.item_delegate)

        for i in range(len(self.model.columns)):
            self.table.setColumnWidth(i, self.item_delegate.sizeHint(self.table.viewOptions(),
                                                                     self.model.index(-1, i, QModelIndex())).width())

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.filter_view)
        self.setLayout(layout)

    def notifyOffsetChanged(self, offset):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

