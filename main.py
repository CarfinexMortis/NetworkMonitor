from ui.main_window import MainWindow
from PyQt5.QtWidgets import QApplication, QMessageBox
import sys
import traceback
from database.db_manager import init_db

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler"""
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(f"Unhandled exception:\n{error_msg}")
    
    # Show error message if GUI is available
    try:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("Critical Error")
        msg.setText("An unexpected error occurred")
        msg.setDetailedText(error_msg)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    except:
        pass
    
    sys.exit(1)

def main():
    try:
        # Set global exception handler
        sys.excepthook = handle_exception
        
        # Check admin privileges on Windows
        if sys.platform == 'win32':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                sys.exit(0)

        # Initialize database with error handling
        try:
            init_db()
        except Exception as db_error:
            QMessageBox.critical(
                None,
                "Database Error",
                f"Failed to initialize database:\n{str(db_error)}"
            )
            return 1

        # Create application
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        
        # Create and show main window
        window = MainWindow()
        
        # Apply saved window state if needed
        if window.settings.get('start_minimized', False):
            window.showMinimized()
        else:
            window.show()

        # Start event loop
        return app.exec_()

    except Exception as e:
        handle_exception(type(e), e, e.__traceback__)
        return 1

if __name__ == "__main__":
    sys.exit(main())