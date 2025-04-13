Dockerfile необходимо поместить в ту же директорию, что и основная программа

Сборка командой
docker build -t sniffer:latest .




Запускается командой
docker run -it --rm   --network host   --cap-add NET_ADMIN   --cap-add NET_RAW   -v sniffer-data:/app/stats   sniffer:latest enp0s8

enp0s8 - имя интерфейса, можно указать любой другой
