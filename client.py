import json
import psutil

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from crypt import Crypt

from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QLineEdit, QFileDialog, QLabel, QMessageBox, \
    QComboBox
from PyQt5.QtCore import pyqtSlot, QDir


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'DNS Steganography'
        self.left = 100
        self.top = 100
        self.width = 600
        self.height = 150
        self.geek_list = ["DNS ID", "TTL"]
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

        # Select method
        self.combo_box = QComboBox(self)
        self.combo_box.move(340, 20)
        self.combo_box.addItems(self.geek_list)

        # Message input
        self.nameLabel = QLabel(self)
        self.nameLabel.setText('Message:')
        self.nameLabel.move(20, 60)

        self.textbox = QLineEdit(self)
        self.textbox.move(120, 60)
        self.textbox.resize(450, 32)

        # Create a button in the window
        self.button = QPushButton('Send message', self)
        self.button.move(10, 100)
        self.button.resize(200, 30)

        self.button_file = QPushButton('Select file', self)
        self.button_file.move(390, 100)
        self.button_file.resize(200, 30)

        # connect button to function on_click
        self.button.clicked.connect(self.on_click)
        self.button_file.clicked.connect(self.on_click_file)
        self.show()

    @pyqtSlot()
    def on_click(self):
        textboxValue = self.textbox.text()
        textboxValueServer = self.textboxServer.text()

        if textboxValueServer == "" or textboxValue == "":
            QMessageBox.about(self, "Error", "Server DNS or message cannot be empty!")
        else:
            self.send_message(textboxValueServer, textboxValue, self.combo_box.currentIndex())
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

    @staticmethod
    def send_message(server, message, method):
        f = open('dns.json')
        data = json.load(f)
        f.close()

        message = Crypt.encrypt(message)

        message += '//'

        print(message)

        start = False

        while not start:
            for proc in psutil.process_iter():
                try:
                    processName = proc.name()
                    processID = proc.pid
                    if "Teams" in processName:
                        print(processName, ' ::: ', processID)
                        start = True
                    else:
                        #print("Teams non in esecuzione")
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        if method == 0:
            for i in range(0, len(message)):
                number_random = random.randint(0, len(data) - 1)
                fake_domain = data[number_random]["dominio"]

                dns_id = random.randint(0, 65535)
                binary_temp = bin(dns_id)[2:].zfill(16)
                binary = binary_temp[:8] + bin(ord(message[i]))[2:].zfill(8)
                new_dns_id = int(binary, 2)

                answer = sr1(
                    IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=new_dns_id, rd=1, z=1,
                                                                                 qd=DNSQR(qname=fake_domain)), verbose=0)

                print(repr(answer[DNS]))
                # time.sleep(random.randint(2, 10))
        else:
            for i in range(0, len(message), 2):
                temp = message[i:i + 2]

                number_random = random.randint(0, len(data) - 1)
                fake_domain = data[number_random]["dominio"]
                ip = data[number_random]["ip"]
                try:
                    ttl = (ord(temp[0]) * 256 + ord(temp[1])) * 2
                except:
                    ttl = (ord(temp[0]) * 256 + ord('/')) * 2

                answer = sr1(
                    IP(dst=server) / UDP(sport=RandShort(), dport=53) / DNS(id=random.randint(0, 65535), rd=1, qd=DNSQR(qname=fake_domain),
                                                                                 an=DNSRR(ttl=ttl, rrname=fake_domain,
                                                                                          rdata=ip)), verbose=0)

                print(repr(answer[DNS]))

                # time.sleep(random.randint(2, 10))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
