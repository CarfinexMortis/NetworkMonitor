from ui.main_window import MainWindow
from PyQt5.QtWidgets import QApplication
import sys
from database.db_manager import init_db  # Import the init_db function to initialize the database

if __name__ == "__main__":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    # Initialize the database (set up tables, etc.)
    init_db()

    # Create the Qt application and main window
    app = QApplication(sys.argv)
    window = MainWindow()

    # Show the main window
    window.show()

    # Start the application's event loop
    sys.exit(app.exec_())
