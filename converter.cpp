#include <iostream>
#include <fstream>
#include <vector>
#include <array>        // ИСПРАВЛЕНИЕ: Добавлен обязательный заголовок для std::array
#include <string>
#include <cstdint>
#include <algorithm>
#include <unordered_map>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

// Подключаем ваш заголовочный файл строки для сборки и вывода путей
#include "iUString.h" 

#pragma pack(push, 1)
struct IPv4BinaryRecord {
    uint32_t ip;
    uint8_t  mask;
    uint8_t  hops;
    uint16_t origin_asn;
};

struct IPv6BinaryRecord {
    uint8_t  ip[16];   // ИСПРАВЛЕНИЕ: Четко зафиксирован массив байт вместо указателя
    uint8_t  mask;
    uint8_t  hops;
    uint16_t origin_asn;
};
#pragma pack(pop)

struct MrtHeader {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

// Хэш-функция для уникальной идентификации IPv6 в контейнерах unordered_map
struct IPv6Hash {
    size_t operator()(const std::array<uint8_t, 16>& k) const {
        size_t h = 0;
        for (auto b : k) h = (h << 5) - h + b;
        return h;
    }
};

uint32_t read_network_32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) | 
           (static_cast<uint32_t>(buf[2]) << 8)  |  static_cast<uint32_t>(buf[3]);
}

uint16_t read_network_16(const uint8_t* buf) {
    return (static_cast<uint16_t>(buf[0]) << 8) | static_cast<uint16_t>(buf[1]);
}

void convert_mrt_to_binary(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open MRT file: " << filepath << std::endl;
        return;
    }

    // Хэш-таблицы в памяти для дедупликации данных "на лету"
    std::unordered_map<uint32_t, IPv4BinaryRecord> ipv4_map;
    std::unordered_map<std::array<uint8_t, 16>, IPv6BinaryRecord, IPv6Hash> ipv6_map;

    std::vector<uint8_t> header_buf(12);
    uint64_t processed_records = 0;

    std::cout << "Starting high-speed conversion... Please wait.\n";

    while (file.read(reinterpret_cast<char*>(header_buf.data()), 12)) {
        MrtHeader header;
        header.timestamp = read_network_32(&header_buf[0]);
        header.type      = read_network_16(&header_buf[4]);
        header.subtype   = read_network_16(&header_buf[6]);
        header.length    = read_network_32(&header_buf[8]);

        std::vector<uint8_t> body(header.length);
        if (!file.read(reinterpret_cast<char*>(body.data()), header.length)) break;

        if (header.type == 13 && (header.subtype == 2 || header.subtype == 4)) {
            size_t offset = 0;
            if (offset + 5 > body.size()) continue;

            offset += 4; // Пропускаем Sequence Number
            uint8_t pfx_len = body[offset]; offset += 1;

            if (pfx_len == 0) continue; // Отсекаем дефолтные маршруты /0

            size_t bytes_to_read = (pfx_len + 7) / 8;
            if (offset + bytes_to_read > body.size()) continue;

            // Сырые байты IP-адреса
            uint8_t raw_ip[16] = {0};
            std::memcpy(raw_ip, &body[offset], (std::min)(bytes_to_read, header.subtype == 2 ? size_t(4) : size_t(16)));
            offset += bytes_to_read;

            // Локальный текстовый фильтр серых сетей (для валидации строк используем ваш iString)
            char ip_c_str[INET6_ADDRSTRLEN] = {0};
            if (header.subtype == 2) {
                inet_ntop(AF_INET, raw_ip, ip_c_str, sizeof(ip_c_str));
                iString<char> check_str(ip_c_str);
                if (check_str.IndexFirst("7.") == 0 || check_str.IndexFirst("10.") == 0 || 
                    check_str.IndexFirst("192.168.") == 0 || check_str.IndexFirst("127.") == 0) {
                    continue; 
                }
            }

            if (offset + 2 > body.size()) continue;
            uint16_t entry_count = read_network_16(&body[offset]); offset += 2;

            for (uint16_t i = 0; i < entry_count; ++i) {
                if (offset + 8 > body.size()) break;
                offset += 6; // Пропускаем Peer Index и Timestamp атрибута
                uint16_t attr_len = read_network_16(&body[offset]); offset += 2;

                if (offset + attr_len > body.size()) break;
                size_t attr_end = offset + attr_len;

                uint8_t total_hops = 0;
                uint16_t last_asn = 0;

                // Парсим внутренности BGP-атрибутов
                while (offset < attr_end) {
                    if (offset + 2 > attr_end) break;
                    uint8_t flags = body[offset];
                    uint8_t attr_type = body[offset + 1];
                    offset += 2;

                    size_t len_bytes = (flags & 0x10) ? 2 : 1;
                    if (offset + len_bytes > attr_end) break;

                    uint16_t current_attr_len = (len_bytes == 1) ? body[offset] : read_network_16(&body[offset]);
                    offset += len_bytes;

                    if (attr_type == 2 && offset + current_attr_len <= attr_end) { // AS_PATH
                        size_t path_offset = offset;
                        size_t path_end = offset + current_attr_len;
                        while (path_offset < path_end) {
                            if (path_offset + 2 > path_end) break;
                            path_offset++; // Пропускаем тип сегмента
                            uint8_t segment_len = body[path_offset]; path_offset += 1;

                            for (uint8_t j = 0; j < segment_len; ++j) {
                                if (path_offset + 4 > path_end) break;
                                uint32_t asn = read_network_32(&body[path_offset]);
                                last_asn = static_cast<uint16_t>(asn & 0xFFFF); // Конечный провайдер
                                total_hops++;
                                path_offset += 4;
                            }
                        }
                    }
                    offset += current_attr_len;
                }

                // Логика дедупликации: оставляем только ОДИН префикс с МИНИМАЛЬНЫМ количеством хопов
                if (total_hops > 0) {
                    if (header.subtype == 2) { // IPv4
                        uint32_t ip_key;
                        std::memcpy(&ip_key, raw_ip, 4);
                        auto it = ipv4_map.find(ip_key);
                        if (it == ipv4_map.end() || total_hops < it->second.hops) {
                            ipv4_map[ip_key] = { ip_key, pfx_len, total_hops, last_asn };
                        }
                    } else if (header.subtype == 4) { // IPv6
                        std::array<uint8_t, 16> ip_key;
                        std::memcpy(ip_key.data(), raw_ip, 16);
                        auto it = ipv6_map.find(ip_key);
                        if (it == ipv6_map.end() || total_hops < it->second.hops) {
                            IPv6BinaryRecord rec;
                            std::memcpy(rec.ip, raw_ip, 16);
                            rec.mask = pfx_len;
                            rec.hops = total_hops;
                            rec.origin_asn = last_asn;
                            ipv6_map[ip_key] = rec;
                        }
                    }
                }
                offset = attr_end;
            }
        }
        if (++processed_records % 200000 == 0) {
            std::cout << "Processed " << processed_records << " MRT blocks...\n";
        }
    }

    // Сортировка массивов перед записью (для быстрой работы std::binary_search)
    std::cout << "Sorting IPv4 arrays...\n";
    std::vector<IPv4BinaryRecord> ipv4_output;
    for (auto& pair : ipv4_map) ipv4_output.push_back(pair.second);
    std::sort(ipv4_output.begin(), ipv4_output.end(), [](const IPv4BinaryRecord& a, const IPv4BinaryRecord& b) {
        return a.ip < b.ip;
    });

    std::cout << "Sorting IPv6 arrays...\n";
    std::vector<IPv6BinaryRecord> ipv6_output;
    for (auto& pair : ipv6_map) ipv6_output.push_back(pair.second);
    std::sort(ipv6_output.begin(), ipv6_output.end(), [](const IPv6BinaryRecord& a, const IPv6BinaryRecord& b) {
        return std::memcmp(a.ip, b.ip, 16) < 0;
    });

    // Сохранение плоских бинарных файлов на диск
    std::ofstream out_v4("ipv4_base.bin", std::ios::binary);
    out_v4.write(reinterpret_cast<const char*>(ipv4_output.data()), ipv4_output.size() * sizeof(IPv4BinaryRecord));

    std::ofstream out_v6("ipv6_base.bin", std::ios::binary);
    out_v6.write(reinterpret_cast<const char*>(ipv6_output.data()), ipv6_output.size() * sizeof(IPv6BinaryRecord));

    std::cout << "\n=== CONVERSION SUCCESSFUL ===\n";
    std::cout << "Saved " << ipv4_output.size() << " clean IPv4 records to ipv4_base.bin\n";
    std::cout << "Saved " << ipv6_output.size() << " clean IPv6 records to ipv6_base.bin\n";
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    convert_mrt_to_binary("rib.mrt");

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
