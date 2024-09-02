from rest_framework.views import APIView
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from django.http import HttpResponse, JsonResponse
from drf_yasg import openapi
from .models import Category, Restaurant, Administrator, Ingredients, Label, Foto, Dish, Order
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import constant_time
import os
import base64
import requests
import random
from django.db import transaction

#Принимает уведомления от Telegram, обрабатывает их
@csrf_exempt
def bottg(request):
    chat = str(json.loads(request.body)['message']['chat']['id'])
    texts = str(json.loads(request.body)['message']['text']).lower()
    if texts == "инфо":
        a = requests.get("https://api.telegram.org/bot6744104810:AAHr3z6BQ2tcaanS-ijtyNF6Fiqcgcn7uv8/sendMessage?chat_id=" + chat + "&text=Ваш ID Telegram: "+ chat)
    else:
        a = requests.get("https://api.telegram.org/bot6744104810:AAHr3z6BQ2tcaanS-ijtyNF6Fiqcgcn7uv8/sendMessage?chat_id=" + chat + "&text=Вы успешно выдали доступ боту на отправку Вам уведомлений\n\nКоманды:\n📌инфо - позволяет получить ID Telegram для указания в системе")
    return HttpResponse("Hi")

def string_to_key(key_string, salt):
    """
    Преобразует строку в криптографический ключ с использованием PBKDF2 и соли.

    :param key_string: Исходная строка для создания ключа.
    :param salt: Случайно сгенерированная соль для увеличения безопасности ключа.
    :return: 32-байтный ключ.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Используем SHA256 в качестве хэш-функции
        length=32,  # Длина выходного ключа 32 байта (256 бит)
        salt=salt,  # Соль для увеличения безопасности
        iterations=100000,  # Количество итераций, увеличивает сложность подбора ключа
        backend=default_backend()  # Бэкэнд для криптографических операций
    )
    return kdf.derive(key_string.encode())  # Генерируем ключ из строки

# Функция для шифрования строки
def encrypt_string(plaintext, key_string):
    """
    Шифрует текст с использованием AES в режиме CBC и строки в качестве ключа.

    :param plaintext: Текст, который нужно зашифровать.
    :param key_string: Строка, используемая для создания ключа шифрования.
    :return: Зашифрованный текст в виде строки, закодированный в base64.
    """
    # Генерация случайной соли для ключа
    salt = os.urandom(16)
    key = string_to_key(key_string, salt)  # Генерация ключа из строки и соли

    # Генерация случайного вектора инициализации (IV)
    iv = os.urandom(16)
    
    # Создание объекта шифра с использованием AES и режима CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()  # Создаем объект шифратора

    # Добавление отступов к тексту для соответствия длине блока AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_text = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Шифрование текста
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    # Возвращаем зашифрованный текст, соединенный с солью и IV, в формате base64
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

# Функция для дешифрования строки
def decrypt_string(ciphertext, key_string):
    """
    Дешифрует зашифрованную строку с использованием AES в режиме CBC и строки в качестве ключа.

    :param ciphertext: Зашифрованный текст в формате base64.
    :param key_string: Строка, используемая для создания ключа шифрования.
    :return: Исходный расшифрованный текст.
    """
    # Декодирование base64 обратно в байты
    ciphertext = base64.b64decode(ciphertext)

    # Извлечение соли, IV и зашифрованного текста из закодированной строки
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    encrypted_text = ciphertext[32:]

    # Генерация ключа из строки и извлеченной соли
    key = string_to_key(key_string, salt)

    # Создание объекта шифра с использованием AES и режима CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()  # Создаем объект дешифратора

    # Дешифрование текста
    decrypted_padded_text = decryptor.update(encrypted_text) + decryptor.finalize()

    # Удаление отступов, добавленных при шифровании
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    # Возвращаем исходный расшифрованный текст
    return decrypted_text.decode('utf-8')

# Пример использования
key_string = "key_sec_misha_zamena"

#Авторизация администратора
class Authorization(APIView):
    #Прописываем документацию для swagger
    @swagger_auto_schema(
        operation_id="Authorization",
        operation_summary="Авторизация администратора в системе",
        operation_description="Данное решение позволяет авторизировать пользователя в системе. На вход принимает параметр yandex_id",
        tags=["Админ. Авторизация"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'yandex_id': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['yandex_id'],
            example={
                'yandex_id': '1357890436',
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                        'token': openapi.Schema(type=openapi.TYPE_STRING),
                        'role': openapi.Schema(type=openapi.TYPE_STRING, description="admin"),
                        'restaurant_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'successfully',
                        'token': 'wamrgjwl3lq5ignkgybhqk3rulvqw3rheh',
                        'role': 'admin',
                        'restaurant_id': 157
                    }
                ),
            ),
        }
    )
    def post(self, request):
        try:
            #Если yandex_id есть
            try:
                yandex_id = request.data.get('yandex_id')
                usern = Administrator.objects.get(id_yandex=str(yandex_id))
            except:
                return Response({"message": "error", "description": "Пользователь по указанным параметрам не найден"})
            ciphertext = encrypt_string(str(usern.id_rest), key_string)
            return Response({
                "message": "successfully",
                "token": str(ciphertext),
                "role": str(usern.status),
                "restaurant_id": int(str(usern.id_rest))
            })
        except:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class Organizations_IIKO(APIView):
    @swagger_auto_schema(
        operation_id="Organizations_IIKO",
        operation_summary="Получение доступных организаций IIKO",
        operation_description="Данное решение позволяет получить список доступных организаций IIKO. На вход принимает токен",
        tags=["IIKO"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                        'organizations': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT)),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'successfully',
                        'organizations': [
                            {
                                "id": "organization_id_1",
                                "name": "Organization 1"
                            },
                            {
                                "id": "organization_id_2",
                                "name": "Organization 2"
                            }
                        ]
                    }
                ),
            ),
        }
    )
    def get(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})
            
            # Получаем токен IIKO и ID организации из объекта ресторана
            iiko_token = restaurant.id_iiko
            iiko_org_id = restaurant.org_iiko
            
            # Авторизуемся в API IIKO и получаем список организаций
            def request_end(url, headers, data):
                json_payload = json.dumps(data)
                response = requests.post(url, headers=headers, data=json_payload)
                return response.json()
            
            # Получаем токен IIKO
            data = {
                "apiLogin": iiko_token
            }
            headers = {
                'Content-Type': 'application/json',
            }
            iiko_api_token = request_end("https://api-ru.iiko.services/api/1/access_token", headers, data).get('token')
            
            if not iiko_api_token:
                return Response({"message": "error", "description": "Ошибка при получении токена IIKO"})
            
            # Получаем список организаций IIKO
            headers = {
                'Content-Type': 'application/json',
                "Authorization": f"Bearer {iiko_api_token}"
            }
            organizations_response = request_end("https://api-ru.iiko.services/api/1/organizations", headers, {})
            
            organizations = organizations_response.get('organizations', [])
            
            return Response({
                "message": "successfully",
                "description": "successfully",
                "organizations": organizations
            })

        except Exception as e:
            return Response({"message": "error", "description": f"Произошла ошибка сервера: {str(e)}"})

class FetchAndSaveMenu(APIView):
    @swagger_auto_schema(
        operation_id="FetchAndSaveMenu",
        operation_summary="Получение и сохранение меню ресторана",
        operation_description="Запрашивает токен IIKO, затем меню с сервиса IIKO и сохраняет его в базе данных, привязывая к ресторану, чей токен передан.",
        tags=["IIKO"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'successfully',
                    }
                ),
            ),
        }
    )
    def post(self, request):
        def Request_end(url, headers, data):
            try:
                headers_end = headers
                data_end = data
                json_payload = json.dumps(data_end)
                response = requests.post(url, headers=headers_end, data=json_payload)
                return response.json()
            except Exception as e:
                return {"error": f"Ошибка при выполнении запроса: {str(e)}"}
        
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                try:
                    restaurant = Restaurant.objects.get(id=int(restaurant_id))
                except Restaurant.DoesNotExist:
                    return Response({"message": "error", "description": "Неверный токен: ресторан не найден"})
            except ValueError:
                return Response({"message": "error", "description": "Неверный токен: ошибка расшифровки"})
            except Exception as e:
                return Response({"message": "error", "description": f"Ошибка при обработке токена: {str(e)}"})

            try:
                # Получаем токен IIKO
                data = {
                    "apiLogin": restaurant.id_iiko
                }
                headers = {
                    'Content-Type': 'application/json',
                }
                iiko_response = Request_end("https://api-ru.iiko.services/api/1/access_token", headers, data)
                if 'error' in iiko_response:
                    return Response({"message": "error", "description": iiko_response['error']})
                iiko_api_token = iiko_response.get('token')
                
                if not iiko_api_token:
                    return Response({"message": "error", "description": "Не удалось получить токен IIKO"})
            except Exception as e:
                return Response({"message": "error", "description": f"Ошибка при получении токена IIKO: {str(e)}"})

            try:
                # Запрашиваем меню из сервиса IIKO
                data = {
                    "organizationId": restaurant.org_iiko,
                    "startRevision": 0
                }
                headers = {
                    'Content-Type': 'application/json',
                    "Authorization": f"Bearer {iiko_api_token}"
                }
                data = Request_end("https://api-ru.iiko.services/api/1/nomenclature", headers, data)
                if 'error' in data:
                    return Response({"message": "error", "description": data['error']})

                for category_data in data['productCategories']:
                    try:
                        cat = Category()
                        cat.name = category_data['name']
                        cat.des = category_data['id']
                        cat.show = True
                        cat.id_rest = restaurant
                        cat.save()
                    except Exception as e:
                        return Response({"message": "error", "description": f"Ошибка при сохранении категории: {str(e)}"})

                for product_data in data['products']:
                    try:
                        category = Category.objects.filter(des=str(product_data['productCategoryId'])).first()
                        for size_price in product_data['sizePrices']:
                            try:
                                dis = Dish()
                                dis.show = True
                                dis.id_rest = restaurant
                                dis.cat_id = category
                                dis.name = str(product_data['name']) if product_data['name'] else "-"
                                dis.weight = float(product_data['weight']) if product_data['weight'] else float(0)
                                dis.cost = float(size_price['price']['currentPrice']) if size_price['price']['currentPrice'] else float(0)
                                dis.cooking_time = "0"
                                dis.kall = "0"
                                dis.description = str(product_data['description']) if product_data['description'] else "-"
                                image_instance = Foto(id=22)
                                dis.photo = image_instance
                                dis.save()
                            except Exception as e:
                                return Response({"message": "error", "description": f"Ошибка при сохранении блюда: {str(e)}"})
                    except Exception as e:
                        return Response({"message": "error", "description": f"Ошибка при обработке продукта: {str(e)}"})
            except Exception as e:
                return Response({"message": "error", "description": f"Ошибка при запросе меню IIKO: {str(e)}"})

            return Response({"message": "successfully", "description": "Меню успешно сохранено"})

        except Exception as e:
            return Response({
                "message": "error",
                "description": f"Произошла ошибка сервера: {str(e)}"
            })
            
class Menu_list(APIView):
    http_method_names = ['get', 'head']
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'parrent': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN)
        }
    )
    @swagger_auto_schema(
        operation_id="Menu_list_get",
        operation_summary="Получение массива элементов категорий меню",
        operation_description="Данное решение позволяет получить массив элементов категорий списков меню. На вход принимает токен авторизации",
        tags=["Админ. Работа с категориями меню"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'description': '',
                        'list': [{
                            "id": 1,
                            "parrent": 0,
                            "name": "Горячие блюда",
                            "show": True
                        }]
                    }
                ),
            ),
        },
    )
    def get(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})

            categories = Category.objects.filter(id_rest=restaurant)
            category_list = [{
                    "id": category.id,
                    "parrent": category.parrent,
                    "name": category.name,
                    "show": category.show
                } for category in categories]
            return Response({
                "message": "successfully",
                "description": "Данные успешно получены",
                "list": category_list
            })
        except Restaurant.DoesNotExist:
            return Response({"message": "error", "description": "Ресторан не найден"})
        except Category.DoesNotExist:
            return Response({"message": "error", "description": "Категории не найдены"})
        except Exception:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class Menu_list_edit(APIView):
    @swagger_auto_schema(
        operation_id="Menu_list_edit",
        operation_summary="Редактирование элемента категорий меню",
        operation_description="Данное решение позволяет отредактировать элемент категорий меню. На вход принимает токен авторизации, ID элемента, новое наименование категории",
        tags=["Админ. Работа с категориями меню"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'id_menu',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'parrent': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID родительской категории (необязательно)"),
            },
            required=['name'],
            example={
                'name': "Напитки",
                'parrent': 1
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки")
                    },
                    example={
                        'message': 'successfully',
                        'description': ''
                    }
                ),
            ),
        }
    )
    def put(self, request, id_menu):
        try:
            name = request.data.get('name')
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            if not id_menu:
                return Response({"message": "error", "description": "ID меню не предоставлен"})
            if not name:
                return Response({"message": "error", "description": "Название не предоставлено"})

            try:
                restaurant_id = decrypt_string(token, key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})

            try:
                category = Category.objects.get(id=int(id_menu))
            except Category.DoesNotExist:
                return Response({"message": "error", "description": "Категория не найдена"})

            if category.id_rest != restaurant:
                return Response({"message": "error", "description": "Категория не принадлежит данному ресторану"})

            category.name = name
            parrent_id = request.data.get('parrent')
            if parrent_id:
                try:
                    parrent_category = Category.objects.get(id=int(parrent_id))
                    category.parrent = parrent_category
                except Category.DoesNotExist:
                    return Response({"message": "error", "description": "Родительская категория не найдена"})
            category.save()

            return Response({
                "message": "successfully",
                "description": "Категория успешно обновлена"
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class Menu_list_create(APIView):
    @swagger_auto_schema(
        operation_id="Menu_list_create",
        operation_summary="Создание элемента категорий меню",
        operation_description="Данное решение позволяет создать элемент категорий меню. На вход принимает токен авторизации, наименование категории",
        tags=["Админ. Работа с категориями меню"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'parrent': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID родительской категории (необязательно)"),
            },
            required=['name'],
            example={
                'name': "Супы",
                'parrent': 1
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Категория успешно создана',
                    }
                ),
            ),
        }
    )
    def post(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен и ID блюда обязательны"})
            name = request.data.get('name')

            # Проверка обязательных параметров
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            if not name:
                return Response({"message": "error", "description": "Название категории не предоставлено"})

            # Декодирование токена и проверка на валидность
            try:
                restaurant_id = decrypt_string(token, key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})
            parrent_id = request.data.get('parrent')
            cat = Category()
            if parrent_id:
                try:
                    parrent_category = Category.objects.get(id=int(parrent_id))
                    cat.parrent = parrent_category
                except Category.DoesNotExist:
                    return Response({"message": "error", "description": "Родительская категория не найдена"})
            # Создание новой категории
            cat.name = name
            cat.show = True
            cat.id_rest = restaurant
            cat.save()

            return Response({
                "message": "successfully",
                "description": "Категория успешно создана"
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера"+str(e)})
            
class Menu_list_delete(APIView):
    @swagger_auto_schema(
        operation_id="Menu_list_delete",
        operation_summary="Удаление элемента категорий меню",
        operation_description="Данное решение позволяет удалить элемент категорий меню. На вход принимает токен авторизации и ID категории.",
        tags=["Админ. Работа с категориями меню"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'id_menu',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Элемент категории успешно удален',
                    }
                ),
            ),
        }
    )
    def delete(self, request, id_menu):
        try:
            name = request.data.get('name')
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            if id_menu is None:
                return Response({"message": "error", "description": "ID категории не предоставлен"})

            # Декодирование токена и проверка его валидности
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})

            # Проверка наличия категории и принадлежности к ресторану
            try:
                category = Category.objects.get(id=int(id_menu))
                if category.id_rest != restaurant:
                    return Response({"message": "error", "description": "Категория не принадлежит данному ресторану"})
            except Category.DoesNotExist:
                return Response({"message": "error", "description": "Категория не найдена"})

            # Удаление категории
            category.delete()

            return Response({
                "message": "successfully",
                "description": "Элемент категории успешно удален"
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class Menu_dish_get(APIView):
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'id_menu': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'description': openapi.Schema(type=openapi.TYPE_STRING),
            'photo': openapi.Schema(type=openapi.TYPE_STRING),
            'label': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
            ),
            'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        }
    )

    @swagger_auto_schema(
        operation_id="Menu_dish_get",
        operation_summary="Получение массива элементов блюд меню",
        operation_description="Данное решение позволяет получить массив элементов блюд меню. На вход принимает токен авторизации.",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'description': '',
                        'list': [{
                            "id": 1,
                            "id_menu": 1,
                            "name": "Суп с грибами",
                            "description": "Вкусный суп с кусочками грибов",
                            "photo": "https://restodev.ru/photo",
                            "cost": 1000.5,
                            'label': ["вегетарианское", "суп"],
                            "show": True,
                        }]
                    }
                ),
            ),
        }
    )
    def get(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})

            # Декодирование токена и проверка его валидности
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен или ресторан не найден"})

            # Получение блюд
            dish_objects = Dish.objects.filter(id_rest=restaurant)
            category_list = []
            for dish in dish_objects:
                labels = dish.label.all()
                label_names = [label.name for label in labels]
                
                # Проверка наличия фото
                try:
                    fot = str(Foto.objects.get(id=int(str(dish.photo))).image.url)
                except Foto.DoesNotExist:
                    fot = str(Foto.objects.get(id=22).image.url)

                category_list.append({
                    "id": int(str(dish.id)),
                    "id_menu": int(str(dish.cat_id)),
                    "name": dish.name,
                    "cost": float(dish.cost),
                    "photo": "https://restodev.ru" + fot,
                    "label": label_names,
                    "description": dish.description,
                    "show": dish.show
                })

            return Response({
                "message": "successfully",
                "description": "",
                "list": category_list
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера "+str(e)})
            
class Menu_dish_edit(APIView):
    @swagger_auto_schema(
        operation_id="Menu_dish_edit",
        operation_summary="Редактирование элемента массива блюд меню",
        operation_description="Данное решение позволяет отредактировать элемент массива блюд меню. На вход принимает токен авторизации и ID блюда. Остальные параметры не являются обязательными",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'dish_id',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'ingredients': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                'weight': openapi.Schema(type=openapi.TYPE_NUMBER),
                'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
                'cooking_time': openapi.Schema(type=openapi.TYPE_STRING),
                'photo_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'label': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                'kall': openapi.Schema(type=openapi.TYPE_INTEGER),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
            },
            example={
                'name': "Суп с грибами",
                'ingredients': ["грибы", "вода", "соль", "лук"],
                'weight': 500.5,
                'cost': 1000.5,
                'cooking_time': "30 минут",
                'label': ["вегетарианское", "суп"],
                'kall': 150,
                'description': "Вкусный суп с кусочками грибов",
                'photo_id': 1,
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'successfully',
                    }
                ),
            ),
        }
    )
    def put(self, request, dish_id):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token or not dish_id:
                return Response({"message": "error", "description": "Токен и ID блюда обязательны"})
            
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except Exception as e:
                return Response({"message": "error", "description": "Ошибка при расшифровке токена или получении ресторана: " + str(e)})
            
            try:
                dish_object = Dish.objects.get(id=int(dish_id))
            except Dish.DoesNotExist:
                return Response({"message": "error", "description": "Блюдо с указанным ID не найдено"})

            if dish_object.id_rest != restaurant:
                return Response({"message": "error", "description": "Блюдо не принадлежит указанному ресторану"})

            # Обновление полей блюда
            def update_field(field_name, default_value):
                value = request.data.get(field_name)
                if value is not None and value != "None":
                    return value
                return default_value

            try:
                dish_object.name = update_field('name', dish_object.name)
                dish_object.weight = update_field('weight', dish_object.weight)
                dish_object.cost = update_field('cost', dish_object.cost)
                dish_object.cooking_time = update_field('cooking_time', dish_object.cooking_time)
                dish_object.kall = update_field('kall', dish_object.kall)
                dish_object.description = update_field('description', dish_object.description)

                ingredients = request.data.get('ingredients')
                if ingredients is not None:
                    ingredient_objs = [Ingredients.objects.get_or_create(name=name)[0] for name in ingredients]
                    dish_object.ingredients.set(ingredient_objs)

                labels = request.data.get('label')
                if labels is not None:
                    label_objs = [Label.objects.get_or_create(name=name)[0] for name in labels]
                    dish_object.label.set(label_objs)
                    
                photo_id = request.data.get('photo_id')
                if photo_id is not None:
                    dish_object.photo = Foto(id=photo_id)

            except Exception as e:
                return Response({"message": "error", "description": "Ошибка при обновлении блюда: " + str(e)})

            dish_object.save()
            return Response({"message": "successfully", "description": "Блюдо успешно обновлено"})

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера: " + str(e)})
        
class Menu_dish_create(APIView):
    @swagger_auto_schema(
        operation_id="Menu_dish_create",
        operation_summary="Создание элемента массива блюд меню",
        operation_description="Данное решение позволяет создать элемент массива блюд меню. На вход принимает токен авторизации и ID категории. Остальные параметры не являются обязательными",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id_menu': openapi.Schema(type=openapi.TYPE_INTEGER),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'ingredients': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                'weight': openapi.Schema(type=openapi.TYPE_NUMBER),
                'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
                'cooking_time': openapi.Schema(type=openapi.TYPE_STRING),
                'photo_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'label': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                ),
                'kall': openapi.Schema(type=openapi.TYPE_INTEGER),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['id_menu'],
            example={
                'id_menu': 1,
                'name': "Суп с грибами",
                'ingredients': ["грибы", "вода", "соль", "лук"],
                'weight': 500.5,
                'cost': 1000.5,
                'cooking_time': "30 минут",
                'label': ["вегетарианское", "суп"],
                'kall': 150,
                'description': "Вкусный суп с кусочками грибов",
                'photo_id': 1,
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Блюдо успешно создано',
                    }
                ),
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен и ID блюда обязательны"})
            id_menu = request.data.get('id_menu')
            try:
                restaurant_id = decrypt_string(str(token), key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
                menu = Category.objects.get(id=int(id_menu))
            except (Restaurant.DoesNotExist, Category.DoesNotExist) as e:
                return Response({"message": "error", "description": "Ошибка при получении ресторана или категории: " + str(e)})

            # Создание нового блюда
            dis = Dish(
                show=True,
                id_rest=restaurant,
                cat_id=menu,
                name=request.data.get('name', ''),
                weight=float(request.data.get('weight', '0')),
                cost=float(request.data.get('cost', '0')),
                cooking_time=request.data.get('cooking_time', ''),
                kall=request.data.get('kall', ''),
                description=request.data.get('description', ''),
            )

            if not dis.name:
                return Response({"message": "error", "description": "Название блюда обязательно"})
            if not dis.weight:
                return Response({"message": "error", "description": "Вес блюда обязателен"})
            if not dis.cost:
                return Response({"message": "error", "description": "Стоимость блюда обязательна"})
            if not dis.cooking_time:
                return Response({"message": "error", "description": "Время приготовления блюда обязательно"})
            if not dis.kall:
                return Response({"message": "error", "description": "Калорийность блюда обязательна"})
            if not dis.description:
                return Response({"message": "error", "description": "Описание блюда обязательно"})

            # Работа с изображением
            photo_id = request.data.get('photo_id')
            if photo_id:
                image_instance = Foto(id=photo_id)
                dis.photo = image_instance
            else:
                image_instance = Foto(id=22)
                dis.photo = image_instance

            dis.save()

            # Обработка ингредиентов
            ingredients = request.data.get('ingredients', [])
            if ingredients:
                ingredient_objs = [Ingredients.objects.get_or_create(name=name)[0] for name in ingredients]
                dis.ingredients.set(ingredient_objs)

            # Обработка меток
            labels = request.data.get('label', [])
            if labels:
                label_objs = [Label.objects.get_or_create(name=name)[0] for name in labels]
                dis.label.set(label_objs)

            return Response({"message": "successfully", "description": "Блюдо успешно создано"})

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера: " + str(e)})
            
class Menu_list_dish_get(APIView):
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'id_menu': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'description': openapi.Schema(type=openapi.TYPE_STRING),
            'photo': openapi.Schema(type=openapi.TYPE_STRING),
            'label': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
            ),
            'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        }
    )

    @swagger_auto_schema(
        operation_id="Menu_list_dish_get",
        operation_summary="Получение массива элементов блюд конкретного меню",
        operation_description="Данное решение позволяет получить массив элементов блюд конкретного меню. На вход принимает токен авторизации, ID категории",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'menu_id',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'list': [{
                            "id": 1,
                            "id_menu": 1,
                            "name": "Суп с грибами",
                            "description": "Вкусный суп с кусочками грибов",
                            "photo": "https://restodev.ru/photo",
                            "cost": 1000.5,
                            'label': ["вегетарианское", "суп"],
                            "show": True,
                        }]
                    }
                ),
            ),
        }
    )
    def get(self, request, menu_id):
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        id_menu = menu_id
        if not token or not id_menu:
            return Response({
                "message": "error",
                "description": "Токен и ID меню обязательны"
            })

        try:
            restaurant_id = decrypt_string(str(token), key_string)
            restaurant = Restaurant.objects.get(id=int(restaurant_id))
            menu = Category.objects.get(id=int(id_menu))
        except (Restaurant.DoesNotExist, Category.DoesNotExist) as e:
            return Response({
                "message": "error",
                "description": "Ресторан или категория не найдены"
            })

        try:
            dish_objects = Dish.objects.filter(id_rest=restaurant, cat_id=menu)
            category_list = []

            for dish in dish_objects:
                labels = dish.label.all()
                label_names = [label.name for label in labels]
                photo_url = ""
                if dish.photo:
                    try:
                        photo_url = str(dish.photo.image.url)
                    except:
                        photo_url = str(Foto.objects.get(id=22).image.url)
                category_list.append({
                    "id": dish.id,
                    "id_menu": dish.cat_id.id,
                    "name": dish.name,
                    "cost": float(dish.cost),
                    "photo": "https://restodev.ru" + photo_url,
                    "label": label_names,
                    "description": dish.description,
                    "show": dish.show
                })

            return Response({
                "message": "successfully",
                "list": category_list
            })

        except Exception as e:
            return Response({
                "message": "error",
                "description": "Произошла ошибка сервера: " + str(e)
            })
            
class Menu_dish_delete(APIView):
    @swagger_auto_schema(
        operation_id="Menu_dish_delete",
        operation_summary="Удаление элемента массива блюд меню",
        operation_description="Данное решение позволяет удалить элемент массива блюд меню. На вход принимает токен авторизации и ID блюда. Остальные параметры не являются обязательными",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'dish_id',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Подробное описание результата"),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Блюдо было успешно удалено.',
                    }
                ),
            ),
        }
    )
    def delete(self, request, dish_id):
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        id_dish = dish_id

        if not token or not id_dish:
            return Response({
                "message": "error",
                "description": "Необходимы токен и ID блюда."
            })

        try:
            restaurant_id = decrypt_string(str(token), key_string)
            restaurant = Restaurant.objects.get(id=int(restaurant_id))
            dish = Dish.objects.get(id=int(id_dish))
            
            if dish.id_rest == restaurant:
                dish.delete()
                return Response({
                    "message": "successfully",
                    "description": "Блюдо было успешно удалено."
                })
            else:
                return Response({
                    "message": "error",
                    "description": "Блюдо не принадлежит указанному ресторану."
                })

        except Restaurant.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Ресторан не найден."
            })
        except Dish.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Блюдо не найдено."
            })
        except Exception as e:
            return Response({
                "message": "error",
                "description": "Произошла непредвиденная ошибка: " + str(e)
            })
            
class Telegram_api(APIView):
    @swagger_auto_schema(
        operation_id="Telegram",
        operation_summary="Отправка уведомлений в телеграм",
        operation_description="Данное решение позволяет отправлять пользователю уведомления в мессенджер Telegram. На вход принимает ID пользователя в телеграм, токен системы, текст сообщения. Пользователь обязательно должен начать диалог с ботом перед использованием (@restodev_bot)",
        tags=["Админ. Телеграм"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING),
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'text': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['token', 'id', 'text'],
            example={
                'token': '4fpgUU3OZxZAdSGlGU2v/xraof07a47/3skLjbTumvE=',
                'id': 1236789567,
                'text': "Успешно отправлено пользователю",
            },
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                    },
                    example={
                        'message': 'successfully',
                    }
                ),
            ),
        }
    )
    def post(self, request):
        try:
            token = str(request.data.get('token'))
            id_tg = str(request.data.get('id'))
            text = str(request.data.get('text'))
            restaurant_id = decrypt_string(str(token), key_string)
            restaurant = Restaurant.objects.get(id=int(restaurant_id))
            a = requests.get("https://api.telegram.org/bot6744104810:AAHr3z6BQ2tcaanS-ijtyNF6Fiqcgcn7uv8/sendMessage?chat_id=" + id_tg + "&text=" + text + "")
            return Response({
                "message": "successfully",
            })
        except:
            return Response({"message": "error"})
            
class Menu_dish_get_definite(APIView):
    @swagger_auto_schema(
        operation_id="Menu_dish_get_definite",
        operation_summary="Получение элементов блюда меню (подробно)",
        operation_description="Данное решение позволяет получить элементы блюда меню. На вход принимает токен авторизации и ID блюда",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'id_dish',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'cat_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'name': openapi.Schema(type=openapi.TYPE_STRING),
                        'ingredients': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                        'weight': openapi.Schema(type=openapi.TYPE_NUMBER),
                        'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
                        'cooking_time': openapi.Schema(type=openapi.TYPE_STRING),
                        'photo': openapi.Schema(type=openapi.TYPE_STRING),
                        'label': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                        'kall': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        'message': 'successfully',
                        'cat_id': 1,
                        'name': 'Суп с грибами',
                        'ingredients': ["грибы", "вода", "соль", "лук"],
                        'weight': 500,
                        'cost': 1000.5,
                        'cooking_time': "30 минут",
                        'photo': 'https://restodev.ru/photo',
                        'label': ["вегетарианское", "суп"],
                        'kall': 150,
                        'show': True,
                        'description': 'Вкусный суп с кусочками грибов',
                    }
                ),
            ),
        }
    )
    def get(self, request, id_dish):
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]

        if not token or not id_dish:
            return Response({
                "message": "error",
                "description": "Необходимы токен и ID блюда."
            })

        try:
            restaurant_id = decrypt_string(str(token), key_string)
            restaurant = Restaurant.objects.get(id=int(restaurant_id))
            dish = Dish.objects.get(id=int(id_dish))

            if dish.id_rest != restaurant:
                return Response({
                    "message": "error",
                    "description": "Блюдо не принадлежит указанному ресторану."
                })

            labels = dish.label.all()
            label_names = [label.name for label in labels]
            ingredients = dish.ingredients.all()
            ingredient_names = [ingredient.name for ingredient in ingredients]

            try:
                photo_url = str(Foto.objects.get(id=int(dish.photo.id)).image.url)
            except Foto.DoesNotExist:
                photo_url = ""

            return Response({
                "message": "successfully",
                "cat_id": dish.cat_id.id,
                "name": dish.name,
                "ingredients": ingredient_names,
                "weight": float(dish.weight),
                "cost": float(dish.cost),
                "cooking_time": dish.cooking_time,
                "photo": "https://restodev.ru" + photo_url,
                "label": label_names,
                "kall": dish.kall,
                "show": dish.show,
                "description": dish.description,
            })
        except Restaurant.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Ресторан не найден."
            })
        except Dish.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Блюдо не найдено."
            })
        except Exception as e:
            return Response({
                "message": "error",
                "description": "Произошла непредвиденная ошибка: " + str(e)
            })
            
class Menu_dish_status(APIView):
    @swagger_auto_schema(
        operation_id="Menu_dish_status",
        operation_summary="Изменение статуса блюда меню",
        operation_description="Данное решение позволяет изменить статус блюда меню. На вход принимает токен авторизации, ID блюда, состояние статуса.",
        tags=["Админ. Работа с блюдами"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'dish_id',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            },
            required=['token'],
            example={
                'status': True,
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="успешно / ошибка"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание блюда"),
                    },
                    example={
                        'message': 'успешно',
                        'description': 'Описание блюда успешно обновлено.',
                    }
                ),
            ),
        }
    )
    def put(self, request, dish_id):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            if not dish_id:
                return Response({"message": "error", "description": "ID блюда не предоставлен"})
            restaurant_id = decrypt_string(token, key_string)
            restaurant = Restaurant.objects.get(id=int(restaurant_id))
            dish_object = Dish.objects.get(id=int(dish_id))
            
            if dish_object.id_rest != restaurant:
                return Response({"message": "ошибка", "description": "Блюдо не принадлежит данному ресторану."})
            
            # Установка нового статуса
            status = str(request.data.get('status')).lower()
            dish_object.show = (status == "true")
            
            # Обновление остальных полей
            dish_object.name = dish_object.name
            dish_object.ingredients.set(dish_object.ingredients.all())
            dish_object.weight = dish_object.weight
            dish_object.cost = dish_object.cost
            dish_object.cooking_time = dish_object.cooking_time
            dish_object.label.set(dish_object.label.all())
            dish_object.kall = dish_object.kall
            dish_object.description = dish_object.description
            dish_object.photo = dish_object.photo
            
            # Сохранение изменений
            dish_object.save()

            return Response({"message": "успешно", "description": "Статус блюда успешно изменен."})
        except Restaurant.DoesNotExist:
            return Response({"message": "ошибка", "description": "Ресторан не найден."})
        except Dish.DoesNotExist:
            return Response({"message": "ошибка", "description": "Блюдо не найдено."})
        except Exception as e:
            return Response({"message": "ошибка", "description": str(e)})
            
class Authorization_number(APIView):
    @swagger_auto_schema(
        operation_id="Authorization_number",
        operation_summary="Авторизация администратора в системе посредством номера телефона и пароля",
        operation_description="Данное решение позволяет авторизировать пользователя в системе посредством номера телефона и пароля. На вход принимает параметр number и password.",
        tags=["Админ. Авторизация"],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'number': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['number', 'password'],
            example={
                'number': '79051757737',
                'password': '12345',
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                        'token': openapi.Schema(type=openapi.TYPE_STRING),
                        'role': openapi.Schema(type=openapi.TYPE_STRING, description="admin"),
                        'restaurant_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Успешная авторизация.',
                        'token': 'wamrgjwl3lq5ignkgybhqk3rulvqw3rheh',
                        'role': 'admin',
                        'restaurant_id': 157
                    }
                ),
            ),
        }
    )
    def post(self, request):
        try:
            try:
                yandex_id = request.data.get('number')
                password = str(request.data.get('password'))
                usern = Administrator.objects.get(number=str(yandex_id))
            except:
                return Response({"message": "error", "description": "Пользователь по указанным параметрам не найден"})
            if str(password) != str(usern.administrator_password):
                return Response({"message": "error", "description": "Пароль или номер телефона не верен"})
            ciphertext = encrypt_string(str(usern.id_rest), key_string)
            return Response({
                "message": "successfully",
                "token": str(ciphertext),
                "role": str(usern.status),
                "restaurant_id": int(str(usern.id_rest))
            })
        except:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class Menu_list_status(APIView):
    @swagger_auto_schema(
        operation_id="Menu_list_status",
        operation_summary="Редактирование статуса категории меню",
        operation_description="Данное решение позволяет отредактировать статус категории меню. На вход принимает токен авторизации, ID элемента, статус",
        tags=["Админ. Работа с категориями меню"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'id_menu',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            },
            required=['status'],
            example={
                'status': True
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Статус категории успешно изменен',
                    }
                ),
            ),
        }
    )
    def put(self, request, id_menu):
        try:
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            status = request.data.get('status')
            # Проверка обязательных параметров
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            if id_menu is None:
                return Response({"message": "error", "description": "ID категории не предоставлен"})
            if status is None:
                return Response({"message": "error", "description": "Статус категории не предоставлен"})

            # Декодирование токена и проверка на валидность
            try:
                restaurant_id = decrypt_string(token, key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})

            # Проверка наличия категории в ресторане
            try:
                category = Category.objects.get(id=int(id_menu))
                if category.id_rest != restaurant:
                    return Response({"message": "error", "description": "Категория не принадлежит данному ресторану"})
            except Category.DoesNotExist:
                return Response({"message": "error", "description": "Категория не найдена"})

            # Обновление статуса категории
            category.show = bool(status)
            category.save()

            return Response({
                "message": "successfully",
                "description": "Статус категории успешно изменен"
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class FotoUploadView(APIView):
    @swagger_auto_schema(
        operation_id="upload_image",
        operation_summary="Загрузка изображения",
        operation_description="Позволяет загружать изображение на сервер. В ответе возвращается ID загруженного файла.",
        tags=["Админ. Изображения"],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Токен авторизации в формате 'Bearer <токен>'",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'image': openapi.Schema(type=openapi.TYPE_FILE, description="Файл изображения"),
                'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание изображения"),
            },
            required=['image'],
            example={
                'image': 'example.jpg',
                'description': 'Описание изображения'
            }
        ),
        responses={
            200: openapi.Response(
                description="Изображение успешно загружено",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID загруженного изображения"),
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                    },
                    example={
                        'id': 1,
                        'message': 'successfully',
                    }
                )
            ),
        }
    )
    def post(self, request):
        try:
            # Получение и проверка токена авторизации
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(' ')[1]
            # Проверка обязательных параметров
            if not token:
                return Response({"message": "error", "description": "Токен не предоставлен"})
            try:
                restaurant_id = decrypt_string(token, key_string)
                restaurant = Restaurant.objects.get(id=int(restaurant_id))
            except (ValueError, Restaurant.DoesNotExist):
                return Response({"message": "error", "description": "Неверный токен"})

            # Получение файла и описания из запроса
            image = request.FILES.get('image')
            description = request.data.get('description', '-')

            if not image:
                return Response({"message": "error", "description": "Изображение не предоставлено"})

            # Сохранение изображения
            foto = Foto.objects.create(image=image, description=description)
            
            return Response({'id': foto.id})
        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class user_Menu_list(APIView):
    http_method_names = ['get', 'head']
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'parrent': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN)
        }
    )
    @swagger_auto_schema(
        operation_id="user_Menu_list_get",
        operation_summary="Получение массива элементов категорий меню",
        operation_description="Данное решение позволяет получить массив элементов категорий списков меню. На вход принимает ID ресторана",
        tags=["Пользователь. Работа с меню"],
        manual_parameters=[
            openapi.Parameter(
                'id_rest',
                openapi.IN_PATH,
                description="ID ресторана, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'description': '',
                        'list': [{
                            "id": 1,
                            "parrent": 0,
                            "name": "Горячие блюда",
                            "show": True
                        }]
                    }
                ),
            ),
        },
    )
    def get(self, request, id_rest):
        try:
            restaurant = Restaurant.objects.get(id=int(id_rest))
            categories = Category.objects.filter(id_rest=restaurant)
            category_list = [{
                    "id": category.id,
                    "parrent": category.parrent,
                    "name": category.name,
                    "show": category.show
                } for category in categories]
            return Response({
                "message": "successfully",
                "description": "Данные успешно получены",
                "list": category_list
            })
        except Restaurant.DoesNotExist:
            return Response({"message": "error", "description": "Ресторан не найден"})
        except Category.DoesNotExist:
            return Response({"message": "error", "description": "Категории не найдены"})
        except Exception:
            return Response({"message": "error", "description": "Произошла ошибка сервера"})
            
class user_Menu_dish_get(APIView):
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'id_menu': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'description': openapi.Schema(type=openapi.TYPE_STRING),
            'photo': openapi.Schema(type=openapi.TYPE_STRING),
            'label': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
            ),
            'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        }
    )

    @swagger_auto_schema(
        operation_id="user_Menu_dish_get",
        operation_summary="Получение массива элементов блюд меню",
        operation_description="Данное решение позволяет получить массив элементов блюд меню. На вход принимает ID ресторана.",
        tags=["Пользователь. Работа с меню"],
        manual_parameters=[
            openapi.Parameter(
                'id_rest',
                openapi.IN_PATH,
                description="ID ресторана, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание ошибки"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'description': '',
                        'list': [{
                            "id": 1,
                            "id_menu": 1,
                            "name": "Суп с грибами",
                            "description": "Вкусный суп с кусочками грибов",
                            "photo": "https://restodev.ru/photo",
                            "cost": 1000.5,
                            'label': ["вегетарианское", "суп"],
                            "show": True,
                        }]
                    }
                ),
            ),
        }
    )
    def get(self, request, id_rest):
        try:
            restaurant = Restaurant.objects.get(id=int(id_rest))
            # Получение блюд
            dish_objects = Dish.objects.filter(id_rest=restaurant)
            category_list = []
            for dish in dish_objects:
                labels = dish.label.all()
                label_names = [label.name for label in labels]
                
                # Проверка наличия фото
                try:
                    fot = str(Foto.objects.get(id=int(str(dish.photo))).image.url)
                except Foto.DoesNotExist:
                    fot = str(Foto.objects.get(id=22).image.url)

                category_list.append({
                    "id": int(str(dish.id)),
                    "id_menu": int(str(dish.cat_id)),
                    "name": dish.name,
                    "cost": float(dish.cost),
                    "photo": "https://restodev.ru" + fot,
                    "label": label_names,
                    "description": dish.description,
                    "show": dish.show
                })

            return Response({
                "message": "successfully",
                "description": "",
                "list": category_list
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера "+str(e)})
            
class user_Menu_list_dish_get(APIView):
    item_schema = openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
            'id_menu': openapi.Schema(type=openapi.TYPE_INTEGER),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'description': openapi.Schema(type=openapi.TYPE_STRING),
            'photo': openapi.Schema(type=openapi.TYPE_STRING),
            'label': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
            ),
            'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
            'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        }
    )

    @swagger_auto_schema(
        operation_id="user_Menu_list_dish_get",
        operation_summary="Получение массива элементов блюд конкретного меню",
        operation_description="Данное решение позволяет получить массив элементов блюд конкретного меню. На вход принимает ID ресторана, ID категории",
        tags=["Пользователь. Работа с меню"],
        manual_parameters=[
            openapi.Parameter(
                'menu_id',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
            openapi.Parameter(
                'id_rest',
                openapi.IN_PATH,
                description="ID ресторана, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'list': openapi.Schema(type=openapi.TYPE_ARRAY, items=item_schema)
                    },
                    example={
                        'message': 'successfully',
                        'list': [{
                            "id": 1,
                            "id_menu": 1,
                            "name": "Суп с грибами",
                            "description": "Вкусный суп с кусочками грибов",
                            "photo": "https://restodev.ru/photo",
                            "cost": 1000.5,
                            'label': ["вегетарианское", "суп"],
                            "show": True,
                        }]
                    }
                ),
            ),
        }
    )
    def get(self, request, menu_id, id_rest):
        id_menu = menu_id
        if not id_rest or not id_menu:
            return Response({
                "message": "error",
                "description": "ID ресторана и ID меню обязательны"
            })

        try:
            restaurant = Restaurant.objects.get(id=int(id_rest))
            menu = Category.objects.get(id=int(id_menu))
        except (Restaurant.DoesNotExist, Category.DoesNotExist) as e:
            return Response({
                "message": "error",
                "description": "Ресторан или категория не найдены"
            })

        try:
            dish_objects = Dish.objects.filter(id_rest=restaurant, cat_id=menu)
            category_list = []

            for dish in dish_objects:
                labels = dish.label.all()
                label_names = [label.name for label in labels]
                photo_url = ""
                if dish.photo:
                    try:
                        photo_url = str(dish.photo.image.url)
                    except:
                        photo_url = str(Foto.objects.get(id=22).image.url)
                category_list.append({
                    "id": dish.id,
                    "id_menu": dish.cat_id.id,
                    "name": dish.name,
                    "cost": float(dish.cost),
                    "photo": "https://restodev.ru" + photo_url,
                    "label": label_names,
                    "description": dish.description,
                    "show": dish.show
                })

            return Response({
                "message": "successfully",
                "list": category_list
            })

        except Exception as e:
            return Response({
                "message": "error",
                "description": "Произошла ошибка сервера: " + str(e)
            })
            
class user_Menu_dish_get_definite(APIView):
    @swagger_auto_schema(
        operation_id="user_Menu_dish_get_definite",
        operation_summary="Получение элементов блюда меню (подробно)",
        operation_description="Данное решение позволяет получить элементы блюда меню. На вход принимает ID блюда",
        tags=["Пользователь. Работа с меню"],
        manual_parameters=[
            openapi.Parameter(
                'id_dish',
                openapi.IN_PATH,
                description="ID, который передается в URL",
                type=openapi.TYPE_INTEGER,
                required=True,  # Если параметр обязателен
            ),
        ],
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'cat_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'name': openapi.Schema(type=openapi.TYPE_STRING),
                        'ingredients': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                        'weight': openapi.Schema(type=openapi.TYPE_NUMBER),
                        'cost': openapi.Schema(type=openapi.TYPE_NUMBER),
                        'cooking_time': openapi.Schema(type=openapi.TYPE_STRING),
                        'photo': openapi.Schema(type=openapi.TYPE_STRING),
                        'label': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                        'kall': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'show': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'description': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        'message': 'successfully',
                        'cat_id': 1,
                        'name': 'Суп с грибами',
                        'ingredients': ["грибы", "вода", "соль", "лук"],
                        'weight': 500,
                        'cost': 1000.5,
                        'cooking_time': "30 минут",
                        'photo': 'https://restodev.ru/photo',
                        'label': ["вегетарианское", "суп"],
                        'kall': 150,
                        'show': True,
                        'description': 'Вкусный суп с кусочками грибов',
                    }
                ),
            ),
        }
    )
    def get(self, request, id_dish):

        try:
            dish = Dish.objects.get(id=int(id_dish))
            labels = dish.label.all()
            label_names = [label.name for label in labels]
            ingredients = dish.ingredients.all()
            ingredient_names = [ingredient.name for ingredient in ingredients]

            try:
                photo_url = str(Foto.objects.get(id=int(dish.photo.id)).image.url)
            except Foto.DoesNotExist:
                photo_url = ""

            return Response({
                "message": "successfully",
                "cat_id": dish.cat_id.id,
                "name": dish.name,
                "ingredients": ingredient_names,
                "weight": float(dish.weight),
                "cost": float(dish.cost),
                "cooking_time": dish.cooking_time,
                "photo": "https://restodev.ru" + photo_url,
                "label": label_names,
                "kall": dish.kall,
                "show": dish.show,
                "description": dish.description,
            })
        except Restaurant.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Ресторан не найден."
            })
        except Dish.DoesNotExist:
            return Response({
                "message": "error",
                "description": "Блюдо не найдено."
            })
        except Exception as e:
            return Response({
                "message": "error",
                "description": "Произошла непредвиденная ошибка: " + str(e)
            })
            
class OrderCreateView(APIView):
    @swagger_auto_schema(
        operation_id="OrderCreate",
        operation_summary="Создание заказа",
        operation_description="Позволяет создать заказ для указанного ресторана и стола, с указанием блюд. Возвращает созданный заказ и сумму заказа.",
        tags=["Пользователь. Работа с меню"],
        manual_parameters=[
            openapi.Parameter(
                'id_rest',
                openapi.IN_PATH,
                description="ID ресторана, к которому относится заказ",
                type=openapi.TYPE_INTEGER,
                required=True,
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'table_id': openapi.Schema(type=openapi.TYPE_STRING, description="ID стола"),
                'dishes': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_INTEGER),
                    description="Список ID блюд"
                ),
            },
            required=['table_id', 'dishes'],
            example={
                'table_id': "A1",
                'dishes': [1, 2, 3]
            }
        ),
        responses={
            200: openapi.Response(
                description="OK",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="successfully / error"),
                        'description': openapi.Schema(type=openapi.TYPE_STRING, description="Описание результата"),
                        'order_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID созданного заказа"),
                        'total_amount': openapi.Schema(type=openapi.TYPE_NUMBER, description="Сумма заказа"),
                    },
                    example={
                        'message': 'successfully',
                        'description': 'Заказ успешно создан',
                        'order_id': 1,
                        'total_amount': 2500.75,
                    }
                ),
            ),
        }
    )
    def post(self, request, id_rest, *args, **kwargs):
        try:
            # Получение данных из запроса
            table_id = request.data.get('table_id')
            dish_ids = request.data.get('dishes', [])

            # Проверка обязательных параметров
            if not table_id:
                return Response({"message": "error", "description": "ID стола обязателен"})
            if not dish_ids:
                return Response({"message": "error", "description": "Необходимо указать хотя бы одно блюдо"})

            # Получение ресторана
            try:
                restaurant = Restaurant.objects.get(id=int(id_rest))
            except Restaurant.DoesNotExist:
                return Response({"message": "error", "description": "Ресторан не найден"})

            # Проверка блюд
            valid_dishes = []
            total_amount = 0
            for dish_id in dish_ids:
                try:
                    dish = Dish.objects.get(id=int(dish_id), id_rest=restaurant)
                    valid_dishes.append(dish)
                    total_amount += dish.cost
                except Dish.DoesNotExist:
                    return Response({"message": "error", "description": f"Блюдо с ID {dish_id} не найдено или не принадлежит указанному ресторану"})

            # Создание заказа
            order = Order(
                id_rest=restaurant,
                table_id=table_id,
                total_amount=total_amount
            )
            order.save()
            order.dishes.set(valid_dishes)

            return Response({
                "message": "successfully",
                "description": "Заказ успешно создан",
                "order_id": order.id,
                "total_amount": total_amount,
            })

        except Exception as e:
            return Response({"message": "error", "description": "Произошла ошибка сервера: " + str(e)})