/*
 * Authorized localhost audit utility for the CS456 heartbeat prototype.
 *
 * Modes:
 *   capture - save one legitimate heartbeat for a replay demonstration
 *   spoof   - send newly forged heartbeat messages
 *   replay  - resend the saved heartbeat unchanged
 *
 * This program only intended for use in CS456 for demonstration purposes. 
 */

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

const std::string MONITOR_HOST = "127.0.0.1";
const int DEFAULT_PORT = 9999;
const std::string DEFAULT_CAPTURE_FILE = "captured_heartbeat.json";

struct Options {
    std::string mode;
    int port = DEFAULT_PORT;
    int count = 5;
    double interval = 0.75;
    double timeout = 10.0;
    std::string filename = DEFAULT_CAPTURE_FILE;
};

void printUsage() {
    std::cout
        << "Usage:\n"
        << "  ./heartbeat_audit capture [--port 9999] [--output file]\n"
        << "  ./heartbeat_audit spoof [--port 9999] [--count 5] [--interval 0.75]\n"
        << "  ./heartbeat_audit replay [--port 9999] [--input file] "
           "[--count 5] [--interval 0.75]\n";
}

bool looksLikeExpectedHeartbeat(const std::string& packet) {
    return packet.find("HEARTBEAT") != std::string::npos
        && packet.find("auth-ticket-service") != std::string::npos;
}

Options parseArguments(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        std::exit(1);
    }

    Options options;
    options.mode = argv[1];

    for (int index = 2; index < argc; ++index) {
        std::string argument = argv[index];

        if (argument == "--port" && index + 1 < argc) {
            options.port = std::stoi(argv[++index]);
        } else if (argument == "--count" && index + 1 < argc) {
            options.count = std::stoi(argv[++index]);
        } else if (argument == "--interval" && index + 1 < argc) {
            options.interval = std::stod(argv[++index]);
        } else if (argument == "--timeout" && index + 1 < argc) {
            options.timeout = std::stod(argv[++index]);
        } else if (argument == "--output" && index + 1 < argc) {
            options.filename = argv[++index];
        } else if (argument == "--input" && index + 1 < argc) {
            options.filename = argv[++index];
        } else {
            std::cerr << "Unknown or incomplete argument: " << argument << '\n';
            printUsage();
            std::exit(1);
        }
    }

    return options;
}

sockaddr_in monitorAddress(int port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (inet_pton(AF_INET, MONITOR_HOST.c_str(), &address.sin_addr) != 1) {
        std::cerr << "Could not create localhost address.\n";
        std::exit(1);
    }

    return address;
}

void captureHeartbeat(const Options& options) {
    int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        std::perror("socket");
        return;
    }

    sockaddr_in address = monitorAddress(options.port);

    if (bind(socketFd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::perror("bind");
        std::cerr << "Stop monitor.py before using capture mode.\n";
        close(socketFd);
        return;
    }

    timeval timeout{};
    timeout.tv_sec = static_cast<int>(options.timeout);
    timeout.tv_usec = static_cast<int>(
        (options.timeout - timeout.tv_sec) * 1000000
    );
    setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    std::cout << "Listening on 127.0.0.1:" << options.port
              << " for one legitimate heartbeat...\n";

    char buffer[4096];
    sockaddr_in sender{};
    socklen_t senderLength = sizeof(sender);

    while (true) {
        ssize_t bytesReceived = recvfrom(
            socketFd,
            buffer,
            sizeof(buffer),
            0,
            reinterpret_cast<sockaddr*>(&sender),
            &senderLength
        );

        if (bytesReceived < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cout << "Capture timed out; no packet was saved.\n";
            } else {
                std::perror("recvfrom");
            }
            close(socketFd);
            return;
        }

        std::string packet(buffer, bytesReceived);

        if (!looksLikeExpectedHeartbeat(packet)) {
            std::cout << "Ignored unexpected UDP packet.\n";
            continue;
        }

        std::ofstream output(options.filename);
        output << packet;
        output.close();

        std::cout << "Captured and saved legitimate heartbeat to "
                  << options.filename << ":\n"
                  << packet << '\n';

        close(socketFd);
        return;
    }
}

void sendPacket(int socketFd, const sockaddr_in& address, const std::string& packet) {
    ssize_t bytesSent = sendto(
        socketFd,
        packet.data(),
        packet.size(),
        0,
        reinterpret_cast<const sockaddr*>(&address),
        sizeof(address)
    );

    if (bytesSent < 0) {
        std::perror("sendto");
    }
}

void spoofHeartbeats(const Options& options) {
    int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        std::perror("socket");
        return;
    }

    sockaddr_in address = monitorAddress(options.port);

    std::cout << "SPOOF: sending " << options.count
              << " forged heartbeat packet(s).\n";

    for (int sequence = 1; sequence <= options.count; ++sequence) {
        double timestamp = std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        std::ostringstream packet;
        packet << "{"
               << "\"type\":\"HEARTBEAT\","
               << "\"service\":\"auth-ticket-service\","
               << "\"instance_id\":\"forged-cpp-attacker\","
               << "\"pid\":0,"
               << "\"sequence\":" << sequence << ","
               << "\"timestamp\":" << timestamp
               << "}";

        sendPacket(socketFd, address, packet.str());
        std::cout << "Sent forged packet " << sequence << ": "
                  << packet.str() << '\n';

        if (sequence < options.count) {
            std::this_thread::sleep_for(
                std::chrono::duration<double>(options.interval)
            );
        }
    }

    close(socketFd);
}

void replayHeartbeat(const Options& options) {
    std::ifstream input(options.filename);
    if (!input) {
        std::cerr << "Could not open replay file: " << options.filename << '\n';
        return;
    }

    std::stringstream savedPacket;
    savedPacket << input.rdbuf();
    std::string packet = savedPacket.str();

    if (!looksLikeExpectedHeartbeat(packet)) {
        std::cerr << "Replay file does not look like an auth-ticket heartbeat.\n";
        return;
    }

    int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        std::perror("socket");
        return;
    }

    sockaddr_in address = monitorAddress(options.port);

    std::cout << "REPLAY: sending the following old packet unchanged:\n"
              << packet << '\n';

    for (int count = 1; count <= options.count; ++count) {
        sendPacket(socketFd, address, packet);
        std::cout << "Replayed packet " << count << ".\n";

        if (count < options.count) {
            std::this_thread::sleep_for(
                std::chrono::duration<double>(options.interval)
            );
        }
    }

    close(socketFd);
}

int main(int argc, char* argv[]) {
    try {
        Options options = parseArguments(argc, argv);

        if (options.mode == "capture") {
            captureHeartbeat(options);
        } else if (options.mode == "spoof") {
            spoofHeartbeats(options);
        } else if (options.mode == "replay") {
            replayHeartbeat(options);
        } else {
            std::cerr << "Unknown mode: " << options.mode << '\n';
            printUsage();
            return 1;
        }
    } catch (const std::exception& error) {
        std::cerr << "Audit tool error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}