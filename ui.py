from . import widget
from PySide2.QtCore import Qt

from .ROPChainWidget import ROPChainWidget
from .ROPGadgetWidget import ROPGadgetWidget

def init_ui():
    widget.register_dockwidget(ROPChainWidget, "ROP Chain", Qt.RightDockWidgetArea, Qt.Vertical, False)
    widget.register_dockwidget(ROPGadgetWidget, "ROP Gadgets", Qt.RightDockWidgetArea, Qt.Vertical, False)
