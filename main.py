from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import datetime
import os
import shutil


# region Подписывание данных


# Подписывание данных
def sign_data(data_file_path, signer_name, signer_private_key_file_path, signer_public_key_file_path, ):
    # Получить ключи из файлов
    signer_private_key = RSA.import_key(open(signer_private_key_file_path).read())
    # Получить хеш
    hash = get_file_hash(data_file_path)
    # Зашифровать хеш закрытым ключом подписывающего
    encrypted_hash = encrypt_hash(hash, signer_private_key)
    # Получить имя2 файла с расширением из пути
    signer_public_key_file_name = os.path.basename(signer_public_key_file_path)
    # Создать сертификат подписи
    certificate = create_certificate(signer_name, signer_public_key_file_name)
    # Создать папку для файлов подписи
    if os.path.exists("Digital signature"):
        shutil.rmtree("Digital signature")
    os.mkdir("Digital signature")
    # Записать зашифрованный хеш в файл и поместить в специальную папку для ЭЦП
    with open("Digital signature/Digital signature.pem", "wb") as f:
        f.write(encrypted_hash)
        # [f.write(x) for x in (encrypted_hash, certificate)]
    # Добавить сертификат
    with open("Digital signature/Digital signature certificate.pem", "a") as f:
        f.write(certificate)
    # Скопировать файл с данными в специальную папку для ЭЦП
    data_file_name = os.path.basename(data_file_path)
    shutil.copyfile(data_file_path, "Digital signature/" + data_file_name)
    # Скопировать файл с открытым ключом отправителя в специальную папку для ЭЦП
    shutil.copyfile(signer_public_key_file_path, "Digital signature/" + signer_public_key_file_name)
    os.rename("Digital signature/" + signer_public_key_file_name, "Digital signature/" + "Signer public key.pem")


# Зашифровать хеш
def encrypt_hash(hash, signer_private_key):
    # Создать сигнатуру по закрытому ключу подписывающего
    signature = pss.new(signer_private_key)
    # Подписать сигнатуру
    return signature.sign(hash)


# Создать сертификат цифровой подписи
def create_certificate(signer_name, signer_public_key_file_name):
    certificate = f"Дата формирования подписи: {datetime.datetime.now().strftime('%d-%m-%Y %H:%M')};\nФИО подписыващего: " \
                  f"{signer_name};\nИмя файла открытого ключа подписи: {signer_public_key_file_name}"
    return certificate


# endregion


# region Проверка подписи

def verification_of_data_digital_signature(encrypted_data_file_path, digital_signature_file_path,
                                           signer_public_key_file_path):
    # Получить ключи из файлов
    signer_public_key = RSA.import_key(open(signer_public_key_file_path).read())
    # Получить зашифрованный хеш из подписи
    with open(digital_signature_file_path, "rb") as f:
        encrypted_hash = f.read()
    # Получить хеш оригинального файла
    original_file_hash = get_file_hash(encrypted_data_file_path)
    # Сравнить отправленный хеш из подписи и хеш файла
    is_hashes_same = verify_hash(encrypted_hash, original_file_hash, signer_public_key)
    return is_hashes_same


# Подтвердить правильность хешей
def verify_hash(encrypted_hash, original_hash, signer_public_key):
    # Создать верификатор по открытому ключу подписывающего
    verifier = pss.new(signer_public_key)
    try:
        # Проверить два хеша на идентичность
        verifier.verify(original_hash, encrypted_hash)
        return True
    except(ValueError, TypeError):
        return False


# endregion


# Получить хеш
def get_file_hash(data_file_path):
    # Создать переменную хеш-функции SHA256
    hash = SHA256.new()
    # Объясить блок оптимального размера
    block = bytearray(128 * 1024)
    # Создать memoryview для предоставления внутренних данных буферного объекта без копирования
    memory_view = memoryview(block)
    # Открыть файл в двоичном режиме ('b') для чтения ('r'). Отключить двойную буферизацию, так как
    # уже используется оптимальный размер блока
    with open(data_file_path, 'rb', buffering=0) as f:
        # iter итерирует то, что в скобках. Второй аргумент для того, чтобы после каждого вызова функции из первого
        # аргумента сравнивать её возвращаемое значение со вторым аргументом и если они равны, то прекращать
        # итерирование
        for n in iter(lambda: f.readinto(memory_view), 0):
            # Обновить хеш
            hash.update(memory_view[:n])
    return hash


# Сгенерировать закрытый и открытый ключи
def generate_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()


# Сохранить закрытый и открытый ключи в файлы
def save_keys(private_key, public_key):
    file = open("Keys/private_key.pem", "wb")
    file.write(private_key)
    file.close()
    file = open("Keys/public_key.pem", "wb")
    file.write(public_key)
    file.close()


if __name__ == '__main__':
    print("1. Сгенерировать ключи\n2. Подписать данные\n3. Проверить подпись\n(1/2/3)")
    mode = input(">")
    if mode == str(1):
        private_key, public_key = generate_keys()
        save_keys(private_key, public_key)
        print("Ключи сгенерированы.")
    elif mode == str(2):
        data_file_path = input("Введите путь к файлу с данными: ")
        private_key_path = input("Введите путь к файлу с закрытым ключом подписывающего: ")
        public_key_path = input("Введите путь к файлу с открытым ключом подписывающего: ")
        signer_name = input("Введите ФИО подписывающего: ")
        sign_data(data_file_path,
                  signer_name,
                  private_key_path,
                  public_key_path)
        print("\nДанные успешно подписаны.")
    elif mode == str(3):
        data_file_path = input("Введите путь к файлу с данными: ")
        digital_signature_path = input("Введите путь к файлу с электронной подписью: ")
        public_key_path = input("Введите путь к файлу с открытым ключом подписывающего: ")
        verification = verification_of_data_digital_signature(data_file_path,
                                               digital_signature_path,
                                               public_key_path)
        if verification:
            print("\nВерификация успешна. Хеши равны. Данные не были изменены или подменены.")
        else:
            print("\nВнимание! Верификация провалилась. Хеши не равны. Данные, вероятно, не соответствуют")
