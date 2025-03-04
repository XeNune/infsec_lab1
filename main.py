import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QMessageBox,
    QLineEdit, QLabel, QHBoxLayout, QListWidget, QInputDialog, QCheckBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class CryptoManager:
    def __init__(self, passphrase):
        """
        Инициализирует объект CryptoManager, генерируя ключ шифрования и случайное значение.
        """
        self.key = self.generate_key(passphrase)
        self.iv = os.urandom(16)  # Генерация случайного значения для потока

    def generate_key(self, passphrase):
        """
        Генерирует ключ шифрования на основе парольной фразы с использованием хэш-функции MD5.
        """
        md5 = hashlib.md5()
        md5.update(passphrase.encode('utf-8'))
        return md5.digest()

    def encrypt(self, plaintext):
        """
        Шифрует переданный текст с использованием AES (стандарт симметричного шифрования) и режима CFB (режим работы AES в виде потока).
        """
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return self.iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext):
        """
        Расшифровывает зашифрованные данные.
        """
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    @staticmethod
    def save_encrypted_file(filename, data):
        """
        Сохраняет зашифрованные данные в указанный файл.
        """
        with open(filename, 'wb') as file:
            file.write(data)

    @staticmethod
    def load_encrypted_file(filename):
        """
        Загружает зашифрованные данные из указанного файла.
        """
        with open(filename, 'rb') as file:
            return file.read()

    @staticmethod
    def encrypt_initial_file(passphrase, filename):
        """
        Шифрует указанный файл, используя парольную фразу, и сохраняет его в новый файл с расширением .enc.
        """
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as file:
                plaintext = file.read()
            crypto = CryptoManager(passphrase)
            encrypted_data = crypto.encrypt(plaintext)
            CryptoManager.save_encrypted_file(filename + ".enc", encrypted_data)
            os.remove(filename)
            print(f"Файл {filename} зашифрован и удалён.")

def initialize_encrypted_file():
    """
    Проверяет наличие файла users.txt.enc и выполняет необходимые действия.
    """
    if not os.path.exists("users.txt.enc"):
        passphrase, ok = QInputDialog.getText(None, "Парольная фраза", "Введите парольную фразу для шифрования:")
        if not ok or not passphrase:
            QMessageBox.critical(None, "Ошибка", "Необходимо указать парольную фразу.")
            sys.exit()

        # Если есть users.txt, шифруем его
        if os.path.exists("users.txt"):
            with open("users.txt", "r", encoding="utf-8") as file:
                plaintext = file.read()
            crypto = CryptoManager(passphrase)
            encrypted_data = crypto.encrypt(plaintext)
            CryptoManager.save_encrypted_file("users.txt.enc", encrypted_data)
            os.remove("users.txt")
            print("Файл users.txt зашифрован и удалён.")
        else:
            # Если users.txt отсутствует, создаем пустой файл и шифруем его
            crypto = CryptoManager(passphrase)
            encrypted_data = crypto.encrypt("")
            CryptoManager.save_encrypted_file("users.txt.enc", encrypted_data)
            print("Создан новый зашифрованный файл users.txt.enc.")

    # Расшифровываем users.txt.enc во временный файл users_temp.txt
    passphrase, ok = QInputDialog.getText(None, "Парольная фраза", "Введите парольную фразу для расшифровки:")
    if not ok or not passphrase:
        QMessageBox.critical(None, "Ошибка", "Необходимо указать парольную фразу.")
        sys.exit()

    try:
        crypto = CryptoManager(passphrase)
        encrypted_data = CryptoManager.load_encrypted_file("users.txt.enc")
        decrypted_data = crypto.decrypt(encrypted_data).decode('utf-8')
        with open("users_temp.txt", "w", encoding="utf-8") as file:
            file.write(decrypted_data)
        print("Файл users.txt.enc успешно расшифрован во временный файл users_temp.txt.")
    except Exception as e:
        QMessageBox.critical(None, "Ошибка", f"Не удалось расшифровать файл: {e}")
        sys.exit()


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Авторизация")
        self.setGeometry(100, 100, 400, 200)
        
        self.initUI()
        self.loadUsersFromFile()
        self.attempts = 0
    
    def initUI(self):
        """
        Инициализирует интерфейс формы авторизации.
        """
        layout = QVBoxLayout()
        
        # Стиль для заголовков
        font = QFont("Arial", 12, QFont.Weight.Bold)

        self.username_label = QLabel("Имя пользователя:")
        self.username_label.setFont(font)
        self.username_input = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        
        self.password_label = QLabel("Пароль:")
        self.password_label.setFont(font)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Войти")
        self.login_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px;")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def loadUsersFromFile(self):
        """
        Загружает данные пользователей из временного файла users_temp.txt.
        """
        try:
            with open("users_temp.txt", "r", encoding="utf-8") as file:
                decrypted_data = file.read()

            if 'ADMIN' not in decrypted_data:
                QMessageBox.critical(self, "Ошибка", "Отсутствует учетная запись администратора.")
                sys.exit()

            lines = decrypted_data.splitlines()[1:]
            self.users = {}
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    is_admin = parts[0].lower() == "true"
                    is_blocked = parts[1].lower() == "true"
                    password_restrictions = parts[2].lower() == "true"
                    username = parts[3]
                    password = parts[4] if len(parts) > 4 else ""
                    self.users[username] = {
                        "password": password,
                        "is_blocked": is_blocked,
                        "is_admin": is_admin,
                        "password_restrictions": password_restrictions
                    }
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить пользователей: {e}")

    def login(self):
        """
        Проверяет введенные данные пользователя и выполняет вход.
        """
        # Перезагружаем пользователей перед проверкой входа
        self.loadUsersFromFile()

        username = self.username_input.text()
        password = self.password_input.text()

        if username not in self.users:
            QMessageBox.critical(self, "Ошибка", "Пользователь не найден.")
            self.attempts += 1
            if self.attempts >= 3:
                QMessageBox.critical(self, "Ошибка", "Превышено количество попыток входа.")
                sys.exit()
            return

        user_data = self.users[username]
        if user_data["is_blocked"]:
            QMessageBox.critical(self, "Ошибка", "Ваш аккаунт заблокирован.")
            return

        if user_data["password"] == "":
            new_password = self.changePasswordOnFirstLogin(username)
            if new_password:
                user_data["password"] = new_password
                self.saveUsersToFile()
                QMessageBox.critical(self, "Успех", "Пароль установлен.")
                return
            else:
                return

        if user_data["password"] == password:
            self.openMainWindow(user_data["is_admin"], username)
        else:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль.")
            self.attempts += 1
            if self.attempts >= 3:
                QMessageBox.critical(self, "Ошибка", "Превышено количество попыток входа.")
                sys.exit()

    def changePasswordOnFirstLogin(self, username):
        """
        Запрашивает новый пароль для пользователя при первом входе.
        """
        while True:
            new_password, confirm_password = self.getNewPasswordFromUser(username)
            if new_password != confirm_password:
                QMessageBox.critical(self, "Ошибка", "Пароли не совпадают.")
                continue
            if self.users[username]["password_restrictions"] and not self.validatePassword(new_password):
                QMessageBox.critical(self, "Ошибка", "Пароль не соответствует требованиям.")
                continue
            return new_password

    def getNewPasswordFromUser(self, username):
        """
        Запрашивает новый пароль и подтверждение пароля от пользователя.
        """
        new_password, _ = QInputDialog.getText(
            self, "Смена пароля", "Введите новый пароль:", QLineEdit.EchoMode.Password
        )
        confirm_password, _ = QInputDialog.getText(
            self, "Подтверждение пароля", "Подтвердите новый пароль:", QLineEdit.EchoMode.Password
        )
        return new_password, confirm_password

    def validatePassword(self, password):
        """
        Проверяет, соответствует ли пароль требованиям.
        Вариант 2. Наличие строчных и прописных букв.
        """
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            return False
        return True

    def saveUsersToFile(self):
        """
        Сохраняет данные пользователей во временный файл users_temp.txt.
        """
        try:
            data = "#| is_admin | is_blocked | password_restrictions | username | password |\n"
            for username, user in self.users.items():
                data += f"{str(user['is_admin']).lower()} {str(user['is_blocked']).lower()} {str(user['password_restrictions']).lower()} {username} {user['password']}\n"

            with open("users_temp.txt", "w", encoding="utf-8") as file:
                file.write(data)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить пользователей: {e}")

    def encrypt_and_cleanup(self):
        """
        Шифрует временный файл users_temp.txt и удаляет его.
        """
        passphrase, ok = QInputDialog.getText(self, "Парольная фраза", "Введите парольную фразу для шифрования:")
        if not ok or not passphrase:
            QMessageBox.critical(self, "Ошибка", "Необходимо указать парольную фразу.")
            return

        try:
            with open("users_temp.txt", "r", encoding="utf-8") as file:
                plaintext = file.read()

            crypto = CryptoManager(passphrase)
            encrypted_data = crypto.encrypt(plaintext)
            CryptoManager.save_encrypted_file("users.txt.enc", encrypted_data)
            os.remove("users_temp.txt")
            print("Файл users_temp.txt зашифрован и удалён.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать файл: {e}")

    def openMainWindow(self, is_admin, username):
        """
        Открывает главное окно приложения после успешного входа.
        """
        self.main_window = MainWindow(is_admin, self.users, username)
        self.main_window.show()
        self.close()


class MainWindow(QMainWindow):
    def __init__(self, is_admin, users, username):
        super().__init__()
        self.is_admin = is_admin
        self.users = users
        self.username = username
        self.setWindowTitle("Приложение")
        self.setGeometry(100, 100, 800, 600)
        
        self.initUI()

    def initUI(self):
        """
        Инициализирует интерфейс главного окна.
        """
        layout = QVBoxLayout()
        
        # Верхняя панель с логаутом
        top_layout = QHBoxLayout()
        self.logout_button = QPushButton("Выйти")
        self.logout_button.setStyleSheet("background-color: #f44336; color: white; font-size: 14px;")
        self.logout_button.clicked.connect(self.logout)
        top_layout.addWidget(self.logout_button)
        top_layout.addStretch()
        layout.addLayout(top_layout)

        # Кнопка смены пароля (для всех пользователей)
        self.change_password_button = QPushButton("Сменить пароль")
        self.change_password_button.setStyleSheet("background-color: #2196F3; color: white; font-size: 14px;")
        self.change_password_button.clicked.connect(self.changePassword)
        layout.addWidget(self.change_password_button)

        # Список пользователей
        if self.is_admin:
            self.user_list = QListWidget()
            self.user_list.itemClicked.connect(self.showUserDetails)
            self.updateUserList()
            layout.addWidget(self.user_list)

            # Панель управления пользователем
            self.user_details_layout = QVBoxLayout()
            self.block_checkbox = QCheckBox("Заблокировать пользователя")
            self.restrictions_checkbox = QCheckBox("Включить ограничения паролей")
            self.save_changes_button = QPushButton("Сохранить изменения")
            self.save_changes_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 14px;")
            self.save_changes_button.clicked.connect(self.saveUserChanges)

            self.add_user_button = QPushButton("Добавить пользователя")
            self.add_user_button.setStyleSheet("background-color: #FFC107; color: white; font-size: 14px;")
            self.add_user_button.clicked.connect(self.addUser)

            self.user_details_layout.addWidget(self.block_checkbox)
            self.user_details_layout.addWidget(self.restrictions_checkbox)
            self.user_details_layout.addWidget(self.save_changes_button)
            self.user_details_layout.addWidget(self.add_user_button)
            layout.addLayout(self.user_details_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def updateUserList(self):
        """
        Обновляет список пользователей в главном окне.
        """
        self.user_list.clear()
        for username, data in self.users.items():
            info = (
                f"{username} - "
                f"{'Админ' if data['is_admin'] else 'Пользователь'}, "
                f"Блокировка: {'Да' if data['is_blocked'] else 'Нет'}, "
                f"Ограничения: {'Да' if data['password_restrictions'] else 'Нет'}"
            )
            self.user_list.addItem(info)

    def showUserDetails(self, item):
        """
        Отображает детали выбранного пользователя.
        """
        details = item.text()
        username = details.split(" - ")[0]
        user_data = self.users[username]
        self.current_user = username
        self.block_checkbox.setChecked(user_data["is_blocked"])
        self.restrictions_checkbox.setChecked(user_data["password_restrictions"])

    def saveUserChanges(self):
        """
        Сохраняет изменения в статусе пользователя (блокировка, ограничения пароля).
        """
        if not hasattr(self, "current_user"):
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя.")
            return

        user_data = self.users[self.current_user]
        user_data["is_blocked"] = self.block_checkbox.isChecked()
        user_data["password_restrictions"] = self.restrictions_checkbox.isChecked()
        self.saveUsersToFile()
        QMessageBox.information(self, "Успешно", "Изменения сохранены.")

    def addUser(self):
        """
        Добавляет нового пользователя в систему.
        """
        new_username, ok = QInputDialog.getText(self, "Добавление пользователя", "Введите имя нового пользователя:")
        if not ok or new_username in self.users:
            QMessageBox.critical(self, "Ошибка", "Имя пользователя недоступно.")
            return
        self.users[new_username] = {
            "password": "",  # Новый пользователь создается с пустым паролем
            "is_blocked": False,
            "is_admin": False,
            "password_restrictions": False
        }
        self.saveUsersToFile()
        self.updateUserList()
        QMessageBox.information(self, "Успешно", "Пользователь добавлен.")

    def changePassword(self):
        """
        Предоставляет возможность пользователю изменить свой пароль.
        """
        old_password, _ = QInputDialog.getText(
            self, "Смена пароля", "Введите старый пароль:", QLineEdit.EchoMode.Password
        )
        if old_password != self.users[self.username]["password"]:
            QMessageBox.critical(self, "Ошибка", "Старый пароль неверный.")
            return
        new_password, confirm_password = self.getNewPasswordFromUser(self.username)
        if new_password != confirm_password:
            QMessageBox.critical(self, "Ошибка", "Пароли не совпадают.")
            return
        if self.users[self.username]["password_restrictions"] and not self.validatePassword(new_password):
            QMessageBox.critical(self, "Ошибка", "Пароль не соответствует требованиям.")
            return
        self.users[self.username]["password"] = new_password
        self.saveUsersToFile()
        QMessageBox.information(self, "Успешно", "Пароль успешно изменен.")

    def getNewPasswordFromUser(self, username):
        """
        Запрашивает новый пароль и подтверждение пароля от пользователя.
        """
        new_password, _ = QInputDialog.getText(
            self, "Смена пароля", "Введите новый пароль:", QLineEdit.EchoMode.Password
        )
        confirm_password, _ = QInputDialog.getText(
            self, "Подтверждение пароля", "Подтвердите новый пароль:", QLineEdit.EchoMode.Password
        )
        return new_password, confirm_password

    def validatePassword(self, password):
        """
        Проверяет, соответствует ли пароль требованиям безопасности.
        """
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            return False
        return True

    def saveUsersToFile(self):
        """
        Сохраняет данные пользователей в файл users.txt.
        """
        try:
            with open("users_temp.txt", "w", encoding="utf-8") as file:
                file.write("#| is_admin | is_blocked | password_restrictions | username | password |\n")
                for username, data in self.users.items():
                    file.write(
                        f"{'true' if data['is_admin'] else 'false'} "
                        f"{'true' if data['is_blocked'] else 'false'} "
                        f"{'true' if data['password_restrictions'] else 'false'} "
                        f"{username} {data['password']}\n"
                    )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить пользователей: {e}")

    def logout(self):
        """
        Выходит из текущего сеанса и возвращает пользователя к форме авторизации.
        """
        self.close()
        self.login_window = LoginWindow()
        self.login_window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Инициализация шифрования и расшифровки
    initialize_encrypted_file()

    # Запуск окна авторизации
    login_window = LoginWindow()
    login_window.show()

    # Обработка выхода
    def on_exit():
        login_window.encrypt_and_cleanup()
        sys.exit()

    app.aboutToQuit.connect(on_exit)
    sys.exit(app.exec())