# Используем официальный образ Python как базовый образ
FROM python:3.9

# Устанавливаем переменную окружения, чтобы Python выводил текст в терминал без буферизации
ENV PYTHONUNBUFFERED=1

# Создаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файл зависимостей в контейнер
COPY requirements.txt /app/

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код проекта в контейнер
COPY . /app/

# Копируем статические файлы в директорию STATIC_ROOT
COPY static /app/staticfiles/

# Открываем порт 8000 для доступа к приложению
EXPOSE 8000

# Запускаем сервер Django
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "project.wsgi:application"]