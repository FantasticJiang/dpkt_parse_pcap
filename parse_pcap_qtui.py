import sys

from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QFontMetrics, QGuiApplication
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QSizeGrip
from dpkt_parse_pcap import parse_pcap


# 本机 175% 缩放下实测：标题 dpkt_pcap_parse 在 260px 宽时刚好完整显示（250px 会变成 dpkt_pcap_pa...），
# 界面文字最小需要约 220px。取 300px，为其他机器的系统字体/缩放差异留一点余量。
MIN_WINDOW_WIDTH = 300
INITIAL_WINDOW_HEIGHT = 110


def configure_high_dpi():
    """高 DPI 设置，必须在创建 QApplication 之前调用。"""
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    # Qt 5.14+ 默认把 1.25 / 1.5 / 1.75 等非整数缩放取整，会造成不同机器上界面比例跳变
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )


def place_window(widget):
    """按屏幕可用区域放置窗口，并保证窗口整体落在可见范围内。"""
    avail = QGuiApplication.primaryScreen().availableGeometry()
    frame = widget.frameGeometry()
    x = avail.left() + int((avail.width() - frame.width()) * 0.42)
    y = avail.top() + int(avail.height() * 0.02)
    x = min(max(x, avail.left()), max(avail.left(), avail.right() - frame.width()))
    y = min(max(y, avail.top()), max(avail.top(), avail.bottom() - frame.height()))
    widget.move(x, y)


class ParseWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.setAcceptDrops(True)  # 启用拖拽功能
        self.setWindowTitle("dpkt_pcap_parse")
        # resize 只设置初始尺寸；配合 setMinimumSize 后，窗口四边/四角仍可自由拖动缩放
        self.resize(MIN_WINDOW_WIDTH, INITIAL_WINDOW_HEIGHT)

        # 字体基于系统默认字体做相对放大，避免写死 pointSize 后随 DPI/系统字体设置漂移
        base_font = QApplication.font()
        hint_font = QFont(base_font)
        hint_font.setPointSizeF(base_font.pointSizeF() * 1.6)
        hint_font.setBold(True)
        self.hint_label = QLabel("请拖拽报文到此处解析")
        self.hint_label.setFont(hint_font)
        self.hint_label.setAlignment(Qt.AlignCenter)

        progress_font = QFont(base_font)
        progress_font.setPointSizeF(base_font.pointSizeF() * 1.2)
        self.number_label = QLabel('已解析报文数：0')  # 创建一个显示数字的标签
        self.number_label.setFont(progress_font)
        self.number_label.setAlignment(Qt.AlignCenter)
        # 预留报文数增长后的文本宽度，避免数字变长时被裁
        self.number_label.setMinimumWidth(
            QFontMetrics(progress_font).horizontalAdvance("已解析报文数：9999999")
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self.hint_label)
        layout.addWidget(self.number_label)
        layout.addWidget(QSizeGrip(self), 0, Qt.AlignBottom | Qt.AlignRight)

        # 下限由内容决定：字体变大时窗口下限自动变宽/变高，文字始终单行完整显示
        hint = self.minimumSizeHint()
        self.setMinimumSize(QSize(max(hint.width(), MIN_WINDOW_WIDTH), hint.height()))

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
    configure_high_dpi()
    app = QApplication(sys.argv)

    parse_widget = ParseWidget()
    # 先 show 后定位，此时 frameGeometry() 才包含标题栏等窗口装饰
    parse_widget.show()
    place_window(parse_widget)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
