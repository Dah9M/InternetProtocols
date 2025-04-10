# Internet Protocols Tracer

##
Трассировка автономных систем. Пользователь вводит

## Основные возможности

- **Трассировка маршрута:** Запускается системная утилита `traceroute` для определения IP-адресов от исходной до целевой точки.
- **Получение информации об AS:** Для каждого IP-адреса выполняется WHOIS-запрос для получения номера автономной системы.
- **Интерфейс командной строки:** Использование модуля `argparse` для запуска скрипт с аргументом `<target>`.
```python
import argparse    # Модуль для обработки аргументов командной строки.
import re          # Модуль для работы с регулярными выражениями.
import subprocess  # Модуль для выполнения внешних команд (используется для вызова traceroute).
from ipwhois import IPWhois, IPDefinedError  # Импорт библиотеки для WHOIS-запросов и обработки ошибок для внутренних IP.
```

# Класс Tracer выполняет трассировку маршрута и получение AS-информации.
# Метод traceroute выполняет системную команду 'traceroute' и извлекает из её вывода IP-адреса.
# Запуск команды traceroute с опцией -n (без разрешения DNS имен).
```python
result = subprocess.run(
    ['traceroute', '-n', self.target],
    stdout=subprocess.PIPE,   # Захватываем стандартный вывод.
    stderr=subprocess.PIPE,   # Захватываем вывод ошибок.
    text=True,                # Вывод в виде строки (а не байтов).
    check=True                # При ошибке вызывается исключение.
)
```



# Метод get_as_info получает информацию об автономной системе для заданного IP.
```python
    def get_as_info(self, ip):
```

# Метод run объединяет результаты трассировки и информацию об AS для каждого узла.
```python    
    def run(self):
```
# IPDefinedError Если IP-адрес внутренний или зарезервированный, возвращаем None.

  ```bash
  python3 Tracer.py <target>
```


# Пример работы

![Пример работы](/Tracer.png)
