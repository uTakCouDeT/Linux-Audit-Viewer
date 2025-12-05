import sys
from PyQt5 import QtWidgets

from audit_viewer.main_window import MainWindow
import audit_helper

HELPER_FLAG = "--run-helper"


def main():
    if HELPER_FLAG in sys.argv:
        return audit_helper.main()

    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
