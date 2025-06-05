# Амирхан - Металлобаза

Веб-приложение для металлобазы с функциями покупки и сдачи металла.

## Развертывание на PythonAnywhere

1. Создайте аккаунт на [PythonAnywhere](https://www.pythonanywhere.com/)
2. В разделе "Web" создайте новое веб-приложение:
   - Выберите Python 3.9
   - Выберите Flask
   - Укажите путь к wsgi.py

3. В консоли выполните:
```bash
git clone https://github.com/ваш-репозиторий/timerhan.git
cd timerhan
pip install -r requirements.txt
```

4. Настройте WSGI файл:
```python
import sys
path = '/home/ваш-username/timerhan'
if path not in sys.path:
    sys.path.append(path)

from wsgi import app as application
```

5. Перезапустите веб-приложение

## Локальный запуск

1. Клонируйте репозиторий
2. Создайте виртуальное окружение:
```bash
python -m venv .venv
source .venv/bin/activate  # для Linux/Mac
.venv\Scripts\activate  # для Windows
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

4. Запустите приложение:
```bash
python app.py
```

## Структура проекта

- `app.py` - основной файл приложения
- `wsgi.py` - файл для запуска на сервере
- `requirements.txt` - зависимости проекта
- `templates/` - HTML шаблоны
- `static/` - статические файлы (CSS, JS, изображения)

## Функционал

- Каталог металлопродукции
- Система заказов
- Корзина покупок
- Прием металлолома
- Административная панель
- Система пользователей
- Восстановление пароля 