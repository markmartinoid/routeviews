#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

// Структура заголовка MRT (RFC 6396)
struct MrtHeader {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

// Функции для безопасного чтения Big Endian из бинарного потока
uint32_t read_network_32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) | 
           (static_cast<uint32_t>(buf[1]) << 16) | 
           (static_cast<uint32_t>(buf[2]) << 8)  | 
            static_cast<uint32_t>(buf[3]);
}

uint16_t read_network_16(const uint8_t* buf) {
    return (static_cast<uint16_t>(buf[0]) << 8) | 
            static_cast<uint16_t>(buf[1]);
}

void parse_mrt_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filepath << std::endl;
        return;
    }

    // Выводим CSV заголовок в стандартный поток вывода (stdout)
    std::cout << "IP_Version,Prefix,Length,AS_Path\n";

    std::vector<uint8_t> header_buf(12);
    while (file.read(reinterpret_cast<char*>(header_buf.data()), 12)) {
        MrtHeader header;
        header.timestamp = read_network_32(&header_buf[0]);
        header.type      = read_network_16(&header_buf[4]);
        header.subtype   = read_network_16(&header_buf[6]);
        header.length    = read_network_32(&header_buf[8]);

        std::vector<uint8_t> body(header.length);
        if (!file.read(reinterpret_cast<char*>(body.data()), header.length)) break;

        // Пропускаем PEER_INDEX_TABLE (Type 13, Subtype 1)
        if (header.type == 13 && header.subtype == 1) {
            continue;
        }

        // Фильтруем TABLE_DUMP_V2 (Type 13): RIB_IPV4_UNICAST (2) и RIB_IPV6_UNICAST (4)
        if (header.type == 13 && (header.subtype == 2 || header.subtype == 4)) {
            size_t offset = 0;
            if (offset + 5 > body.size()) continue;

            uint32_t seq = read_network_32(&body[offset]); offset += 4;
            uint8_t pfx_len = body[offset]; offset += 1;

            // КРИТИЧЕСКИЙ ФИЛЬТР 1: Пропускаем дефолтные маршруты (/0)
            if (pfx_len == 0) {
                size_t bytes_to_read = (pfx_len + 7) / 8;
                offset += bytes_to_read;
                continue; 
            }

            size_t bytes_to_read = (pfx_len + 7) / 8;
            if (offset + bytes_to_read > body.size()) continue;

            char ip_str[INET6_ADDRSTRLEN] = {0};
            
            if (header.subtype == 2) { // IPv4
                in_addr addr = {0};
                std::memcpy(&addr, &body[offset], (std::min)(bytes_to_read, size_t(4)));
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            } else if (header.subtype == 4) { // IPv6
                in6_addr addr = {0};
                std::memcpy(&addr, &body[offset], (std::min)(bytes_to_read, size_t(16)));
                inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
            }
            offset += bytes_to_read;

            std::string ip_std_str(ip_str);

            // КРИТИЧЕСКИЙ ФИЛЬТР 2: Проверка префиксов IPv4 на служебные и тестовые сети
            if (header.subtype == 2) {
                if (ip_std_str.rfind("7.", 0) == 0 ||       // Военные сети США (DoD / AS749)
                    ip_std_str.rfind("10.", 0) == 0 ||      // Локальные сети Class A
                    ip_std_str.rfind("192.168.", 0) == 0 || // Домашние подсети Class C
                    ip_std_str.rfind("0.", 0) == 0 ||       // Текущая сеть (RFC 1122)
                    ip_std_str.rfind("127.", 0) == 0 ||     // Loopback localhost
                    ip_std_str.rfind("169.254.", 0) == 0 || // Link-Local (APIPA)
                    ip_std_str.rfind("172.16.", 0) == 0) {  // Локальные сети Class B
                    continue; 
                }
            }

            // КРИТИЧЕСКИЙ ФИЛЬТР 3: Проверка префиксов IPv6 на служебные сети
            if (header.subtype == 4) {
                if (ip_std_str.rfind("fe80:", 0) == 0 || // Link-local
                    ip_std_str.rfind("fc00:", 0) == 0 || // Unique Local (ULA)
                    ip_std_str.rfind("ff00:", 0) == 0 || // Multicast
                    ip_std_str == "::1") {               // Loopback localhost
                    continue;
                }
            }

            if (offset + 2 > body.size()) continue;
            uint16_t entry_count = read_network_16(&body[offset]); offset += 2;

            for (uint16_t i = 0; i < entry_count; ++i) {
                if (offset + 8 > body.size()) break;
                uint16_t peer_index = read_network_16(&body[offset]); offset += 2;
                uint32_t orig_time = read_network_32(&body[offset]); offset += 4;
                uint16_t attr_len = read_network_16(&body[offset]); offset += 2;

                if (offset + attr_len > body.size()) break;

                size_t attr_end = offset + attr_len;
                std::string as_path_str = "";

                while (offset < attr_end) {
                    if (offset + 2 > attr_end) break;
                    uint8_t flags = body[offset];
                    uint8_t attr_type = body[offset + 1];
                    offset += 2;

                    size_t len_bytes = (flags & 0x10) ? 2 : 1; 
                    if (offset + len_bytes > attr_end) break;

                    uint16_t current_attr_len = 0;
                    if (len_bytes == 1) {
                        current_attr_len = body[offset];
                    } else {
                        current_attr_len = read_network_16(&body[offset]);
                    }
                    offset += len_bytes;

                    // Извлекаем цепочку AS_PATH (Type 2)
                    if (attr_type == 2 && offset + current_attr_len <= attr_end) {
                        size_t path_offset = offset;
                        size_t path_end = offset + current_attr_len;
                        while (path_offset < path_end) {
                            if (path_offset + 2 > path_end) break;
                            uint8_t segment_type = body[path_offset];
                            uint8_t segment_len = body[path_offset + 1];
                            path_offset += 2;

                            for (uint8_t j = 0; j < segment_len; ++j) {
                                if (path_offset + 4 > path_end) break;
                                uint32_t asn = read_network_32(&body[path_offset]);
                                as_path_str += std::to_string(asn) + " ";
                                path_offset += 4;
                            }
                        }
                    }
                    offset += current_attr_len;
                }

                if (!as_path_str.empty()) as_path_str.pop_back();

                // Печатаем чистую запись в CSV
                std::cout << (header.subtype == 2 ? "IPv4" : "IPv6") << ","
                          << ip_str << ","
                          << static_cast<int>(pfx_len) << ","
                          << "\"" << as_path_str << "\"\n";

                offset = attr_end; 
            }
        }
    }
}

int main() {
#ifdef _WIN32
    // На Windows инициализируем WinSock, чтобы работал метод inet_ntop
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }
#endif

    // Имя вашего распакованного файла RIB (например, из архива RIPE RIS bview)
    std::string local_mrt_file = "rib.mrt";

    parse_mrt_file(local_mrt_file);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
