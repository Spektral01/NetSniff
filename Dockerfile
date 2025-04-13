# Этап сборки
FROM gcc:12 AS builder

RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    libpcap-dev \
    libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY *.c *.h /app/
RUN gcc -o af_packet_sniffer main.c csv_writer.c -lpcap -lpthread -Wall -O2

# Финальный образ
FROM debian:bookworm-slim

RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list && \
    apt-get update && apt-get install -y \
    libpcap0.8 \
    libsctp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/af_packet_sniffer /app/

ENTRYPOINT ["/app/af_packet_sniffer"]
CMD ["enp0s8"]
