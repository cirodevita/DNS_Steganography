import json
import time
import signal
from configparser import ConfigParser

signal.signal(signal.SIGINT, signal.SIG_DFL)

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLineEdit, QFileDialog, QLabel, QMessageBox, \
    QListWidget, QListWidgetItem, QAbstractItemView
from PyQt5.QtCore import pyqtSlot, QDir
from PyQt5 import Qt

from crypt import Crypt


class WorkThread(Qt.QThread):
    threadSignal = Qt.pyqtSignal(str)

    def __init__(self, server, message):
        super().__init__()
        self.server = server
        self.message = message

    def countConsonants(self, string):
        vowel = set("aeiouAEIOU")
        v_count = 0
        c_count = 0
        for i in string:
            if i in vowel:
                v_count = v_count + 1
            elif ('a' <= i <= 'z') or ('A' <= i <= 'Z'):
                c_count += 1

        return c_count, v_count

    def chunkstring(self, string, length):
        return (string[0 + i:length + i] for i in range(0, len(string), length))

    def send_message(self, server, message):
        config = ConfigParser()
        config.read('../configuration.ini')

        f = open('dns.json')
        data = json.load(f)
        f.close()

        message = Crypt.encrypt(message)
        self.threadSignal.emit(message)

        found_domain = False

        start_time = time.time()

        # RUMORE
        request_number = random.randint(5, 10)
        for i in range(0, request_number):
            number_random = random.randint(0, len(data) - 1)
            fake_domain = data[number_random]["dominio"]
            ip = data[number_random]["ip"]

            answer = sr1(
                IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=random.randint(0, 65535), rd=1,
                                                                        qd=DNSQR(qname=fake_domain),
                                                                        an=DNSRR(rrname=fake_domain,
                                                                                 rdata=ip)), verbose=0)
            self.threadSignal.emit(repr(answer[DNS]))
            # time.sleep(random.randint(2, 10))

        while not found_domain:
            number_random = random.randint(0, len(data) - 1)
            fake_domain = data[number_random]["dominio"]
            ip = data[number_random]["ip"]

            if self.countConsonants(fake_domain)[0] % 2 == 0 and self.countConsonants(fake_domain)[1] >= 4:
                found_domain = True

        ttl = random.randint(2468, 10468)
        ttl_binary = bin(ttl)[2:].zfill(16)
        len_binary = bin(len(message))[2:].zfill(8)
        # pattern = random.randint(0, 15)
        # pattern_bin = bin(pattern)[2:].zfill(4)
        pattern_bin = config.get('CONFIG', 'pattern')

        binary = ''
        j = 0
        k = 0
        for i in range(0, len(ttl_binary)):
            if i % 2 != 0:
                binary += len_binary[j]
                j += 1
            elif i < 8 and i % 2 == 0:
                binary += pattern_bin[k]
                k += 1
            else:
                binary += ttl_binary[i]

        answer = sr1(
            IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=random.randint(0, 65535), rd=1,
                                                                    qd=DNSQR(qname=fake_domain),
                                                                    an=DNSRR(ttl=int(binary, 2), rrname=fake_domain,
                                                                             rdata=ip)), verbose=0)
        self.threadSignal.emit(repr(answer[DNS]))
        # time.sleep(random.randint(2, 10))

        chunks = list(self.chunkstring(message, 16))
        for message in chunks:
            for i in range(0, len(message)):
                found_domain = False

                while not found_domain:
                    number_random = random.randint(0, len(data) - 1)
                    fake_domain = data[number_random]["dominio"]

                    if self.countConsonants(fake_domain)[0] % 2 == 0 and self.countConsonants(fake_domain)[1] >= 4:
                        found_domain = True

                dns_id = random.randint(0, 65535)
                binary_temp = bin(dns_id)[2:].zfill(16)
                binary = ''
                message_binary = bin(ord(message[i]))[2:].zfill(8)
                sequence_number = bin(i)[2:].zfill(4)
                j = 0
                k = 0
                z = 0
                for i in range(0, len(binary_temp)):
                    if i % 2 == 0:
                        binary += message_binary[j]
                        j += 1
                    elif i < 8 and i % 2 != 0:
                        binary += sequence_number[k]
                        k += 1
                    else:
                        binary += pattern_bin[z]
                        z += 1

                new_dns_id = int(binary, 2)

                answer = sr1(
                    IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=new_dns_id, rd=1,
                                                                            qd=DNSQR(qname=fake_domain)), verbose=0)

                self.threadSignal.emit(repr(answer[DNS]))
                # time.sleep(random.randint(2, 10))

                # RUMORE
                request_number = random.randint(1, 3)
                for i in range(0, request_number):
                    number_random = random.randint(0, len(data) - 1)
                    fake_domain = data[number_random]["dominio"]
                    answer = sr1(
                        IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=random.randint(0, 65535), rd=1,
                                                                                qd=DNSQR(qname=fake_domain)), verbose=0)
                    self.threadSignal.emit(repr(answer[DNS]))
                    # time.sleep(random.randint(2, 10))

        end_time = (time.time() - start_time)
        self.threadSignal.emit("END in " + str(end_time) + " seconds")

    def run(self, *args, **kwargs):
        self.send_message(self.server, self.message)


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'DNS Steganography'
        self.left = 100
        self.top = 100
        self.width = 600
        self.height = 300
        # self.geek_list = ["DNS ID", "TTL"]
        self.thread = None
        self.threadMain = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setFixedSize(self.width, self.height)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # Server Name input
        self.serverName = QLabel(self)
        self.serverName.setText('DNS Server:')
        self.serverName.move(20, 20)

        self.textboxServer = QLineEdit(self)
        self.textboxServer.move(120, 20)
        self.textboxServer.resize(200, 32)
        self.textboxServer.setPlaceholderText("Enter server DNS address ...")

        # Message input
        self.nameLabel = QLabel(self)
        self.nameLabel.setText('Message:')
        self.nameLabel.move(20, 60)

        self.textbox = QLineEdit(self)
        self.textbox.move(120, 60)
        self.textbox.resize(450, 32)
        self.textbox.setPlaceholderText("Enter the message to send ...")

        # Button send message
        self.button = QPushButton('Send message', self)
        self.button.move(10, 100)
        self.button.resize(200, 30)

        # Button clear logger
        self.clear = QPushButton('Clear', self)
        self.clear.move(200, 100)
        self.clear.resize(200, 30)

        # Button select file
        self.button_file = QPushButton('Select file', self)
        self.button_file.move(390, 100)
        self.button_file.resize(200, 30)

        # Logger
        self.list_widget = QListWidget(self)
        self.list_widget.resize(580, 150)
        self.list_widget.move(10, 140)

        # connect button to function on_click
        self.button.clicked.connect(self.on_click)
        # connect button to function on_click_file
        self.button_file.clicked.connect(self.on_click_file)
        # connect button to function on_click_file
        self.clear.clicked.connect(self.on_click_clear)

        self.show()

    @pyqtSlot()
    def on_click(self):
        textboxValue = self.textbox.text()
        textboxValueServer = self.textboxServer.text()

        if textboxValueServer == "" or textboxValue == "":
            QMessageBox.about(self, "Error", "Server DNS or message cannot be empty!")
        else:
            if self.thread is None:
                self.thread = WorkThread(textboxValueServer, textboxValue)
                self.thread.threadSignal.connect(self.on_threadSignal)
                self.thread.start()

                self.button.setText("Stop")
            else:
                self.thread.terminate()
                self.thread = None
                self.button.setText("Send message")

    def on_threadSignal(self, value):
        self.list_widget.addItem(QListWidgetItem(value))
        QAbstractItemView.scrollToBottom(self.list_widget)

        if "END" in value:
            self.thread = None
            self.button.setText("Send message")
            self.textbox.setText("")

    @pyqtSlot()
    def on_click_file(self):
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setFilter(QDir.Files)
        dialog.setNameFilter("Text Files (*.txt)")

        if dialog.exec_():
            file_name = dialog.selectedFiles()
            if file_name[0].endswith('.txt'):
                with open(file_name[0], 'r') as f:
                    message = f.read()
                    self.textbox.setText(message)
                    f.close()
        else:
            pass

    @pyqtSlot()
    def on_click_clear(self):
        QListWidget.clear(self.list_widget)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
