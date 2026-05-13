"""
DDoS Analyzer — Network Security Monitor
=========================================
Phân tích và phát hiện tấn công DDoS thông qua log mạng / file PCAP.

Cách chạy:
    python main.py
    hoặc kéo file .pcap vào cửa sổ chương trình.

Yêu cầu:
    pip install -r requirements.txt
"""
import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s  %(name)s  %(message)s",
)

try:
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from PyQt5.QtCore import Qt
except ImportError:
    print("Lỗi: PyQt5 chưa được cài đặt.")
    print("Chạy lệnh:  pip install PyQt5")
    sys.exit(1)

try:
    from src.ui.main_window import MainWindow
except Exception as exc:
    # Fallback: show error in console
    print(f"Lỗi khởi tạo ứng dụng: {exc}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("DDoS Analyzer")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Network Security Lab")

    win = MainWindow()
    win.setAcceptDrops(True)
    win.show()

    # If a .pcap file was passed as argument, open it directly
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isfile(path) and path.endswith((".pcap", ".pcapng")):
            win._load_file(path)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
