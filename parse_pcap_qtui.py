from PyQt5.QtCore import QSize
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QDesktopWidget, QPushButton, QDialog
from dpkt_parse_pcap import parse_pcap


class ParseWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.setAcceptDrops(True)  # 启用拖拽功能
        self.setWindowTitle("dpkt_pcap_parse")
        self.setFixedSize(QSize(300, 120))

        hint_font = QFont()
        hint_font.setPointSize(16)
        hint_font.setBold(True)
        self.hint_label = QLabel("请拖拽报文到此处解析")
        self.hint_label.setFont(hint_font)

        progress_font = QFont()
        progress_font.setPointSize(12)
        self.number_label = QLabel('已解析报文数：0')  # 创建一个显示数字的标签
        self.number_label.setFont(progress_font)


        layout = QVBoxLayout(self)
        layout.addWidget(self.hint_label)
        layout.addWidget(self.number_label)



    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():  # 如果拖拽的内容包含URLs（文件路径就是一种URL）
            event.acceptProposedAction()  # 接受这个拖拽事件

    def dropEvent(self, event):
        # 获取拖拽的文件路径，mimeData().urls()返回的是一个URL列表，这里我们只取第一个URL（第一个文件的路径）
        file_path = event.mimeData().urls()[0].toLocalFile()
        parse_pcap(file_path, self)

    def refresh_number(self, num):
        self.number_label.setText(f"已解析报文数：{str(num)}")  # 在标签中显示新的数字
        self.number_label.repaint()



def main():
    app = QApplication([])

    parse_widget = ParseWidget()

    screen = QDesktopWidget().screenGeometry()
    left = screen.width() * 0.42
    top = screen.height() * 0.02
    parse_widget.move(left, top)

    parse_widget.show()

    app.exec()


if __name__ == "__main__":
    main()