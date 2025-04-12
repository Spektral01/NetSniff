# Этап сборки
FROM gcc:latest as builder

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем ВСЕ файлы из текущей директории
COPY . /app/

# Компилируем программу
RUN gcc -o af_packet_sniffer main.c csv_writer.c -lpcap -lpthread

# Создаем финальный образ
FROM debian:bookworm-slim

# Устанавливаем библиотеки для запуска
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libsctp1 \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
COPY --from=builder /app/af_packet_sniffer /app/

ENTRYPOINT ["/app/af_packet_sniffer"]
CMD ["eth0"]
