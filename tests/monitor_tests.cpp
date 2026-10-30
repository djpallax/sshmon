// SPDX-License-Identifier: GPL-3.0-or-later
// Self-contained parser and throughput tests using synthetic input only.
// IP addresses are reserved documentation examples (RFC 5737 / RFC 3849).
// No SSH connections, system services, or host network data are accessed.

#include "monitor.h"

#include <QCoreApplication>
#include <QDebug>

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <optional>

namespace {

void expect(bool condition, const char *message) {
    if (!condition) {
        qCritical() << "FAILED:" << message;
        std::exit(EXIT_FAILURE);
    }
}

bool nearlyEqual(const std::optional<double> &actual, double expected) {
    return actual.has_value() && std::abs(*actual - expected) < 0.001;
}

void testIpParsing() {
    expect(normalizeIp("[::ffff:192.0.2.10]") == "192.0.2.10",
           "IPv4-mapped IPv6 normalization");
    expect(normalizeIp("[2001:db8::10]") == "2001:db8::10",
           "Documentation IPv6 normalization");
    expect(splitEndpoint("[2001:db8::10]:54321") ==
               qMakePair(QString("2001:db8::10"), QString("54321")),
           "Bracketed IPv6 endpoint parsing");
}

void testSessionParsing() {
    const QString fakeListing =
        "s1 1000 example-user-1 - pts/1\n"
        "s2 1001 example-local-user seat0 tty1\n"
        "s3 1002 example-user-2 - pts/3\n"
        "s4 1003 example-other-service - pts/4\n";
    const QHash<QString, QString> fakeDetails{
        {"s1", "Service=sshd\nRemote=yes\nName=example-user-1\n"
                "RemoteHost=::ffff:192.0.2.10\nTTY=pts/1\nState=active\n"},
        {"s2", "Service=login\nRemote=no\nName=example-local-user\n"},
        {"s3", "Service=sshd\nRemote=yes\nName=example-user-2\n"
                "RemoteHost=198.51.100.25\nTTY=pts/3\nState=active\n"},
        {"s4", "Service=some-other-service\nRemote=yes\n"
                "Name=example-other-service\nRemoteHost=203.0.113.5\n"},
    };

    const auto sessions = parseSessions(fakeListing, fakeDetails);
    expect(sessions.size() == 2, "Only authenticated remote sshd sessions are included");
    expect(sessions.at(0).id == "s1" && sessions.at(0).host == "192.0.2.10",
           "Synthetic first session is parsed and normalized");
    expect(sessions.at(1).id == "s3" && sessions.at(1).host == "198.51.100.25",
           "Synthetic second session is parsed");
}

void testSocketParsing() {
    const QString fakeSsOutput =
        "0 0 203.0.113.10:22 192.0.2.10:50000\n"
        "\t cubic rtt:12.0 bytes_sent:1024 bytes_received:2048\n"
        "ESTAB 0 0 [2001:db8::20]:22 [2001:db8::10]:50001\n"
        "\t cubic bytes_sent:100 bytes_received:200\n";

    const auto sockets = parseSockets(fakeSsOutput);
    expect(sockets.size() == 2, "Both ss output header formats are recognized");
    expect(sockets.at(0).host == "192.0.2.10" &&
               sockets.at(0).localPort == "22" &&
               sockets.at(0).remotePort == "50000",
           "Synthetic TCP peer and port parsing");
    expect(sockets.at(0).sent == 1024 && sockets.at(0).received == 2048,
           "TCP byte counters are parsed");
    expect(sockets.at(1).host == "2001:db8::10" && sockets.at(1).received == 200,
           "IPv6 TCP counters are parsed");
}

void testThroughput() {
    const auto start = std::chrono::steady_clock::time_point{};

    Snapshot first;
    first.timestamp = start;
    first.sockets = {
        {"192.0.2.10", "50000", "22", 1024, 2048},
        {"192.0.2.10", "50001", "22", 200, 400},
    };
    Throughput tracker;
    const auto initialRates = tracker.calculate(first);
    expect(initialRates.contains("192.0.2.10") &&
               !initialRates.value("192.0.2.10").up.has_value(),
           "First sample has no rate without an earlier counter");

    Snapshot second = first;
    second.timestamp = start + std::chrono::seconds(2);
    second.sockets[0].sent = 3072;     // +2048 bytes in 2 seconds
    second.sockets[0].received = 4096; // +2048 bytes in 2 seconds
    second.sockets[1].sent = 1224;     // +1024 bytes in 2 seconds
    second.sockets[1].received = 1424; // +1024 bytes in 2 seconds
    const auto rates = tracker.calculate(second);
    expect(nearlyEqual(rates.value("192.0.2.10").up, 1536.0),
           "Outgoing bytes per second are aggregated by remote IP");
    expect(nearlyEqual(rates.value("192.0.2.10").down, 1536.0),
           "Incoming bytes per second are aggregated by remote IP");

    Snapshot third = second;
    third.timestamp = start + std::chrono::seconds(4);
    third.sockets[1].sent = std::nullopt;
    const auto partialRates = tracker.calculate(third);
    expect(!partialRates.value("192.0.2.10").up.has_value(),
           "Missing counters must not produce misleading partial totals");
}

void testReconnectSessions() {
    // Reconnection to the same host results in a NEW loginctl session ID.
    // This uses fictional usernames and RFC 5737 documentation addresses.
    const QString ip = "192.0.2.44";
    const auto one = parseSessions("s101 1000 mock-user - pts/0\n", {
        {"s101", "Service=sshd\nRemote=yes\nName=mock-user\nRemoteHost=" + ip + "\n"}
    });
    expect(one.size() == 1 && one.first().id == "s101", "Initial login detected");
    const auto empty = parseSessions("", {});
    expect(empty.isEmpty(), "Disconnect produces an empty snapshot");
    const auto second = parseSessions("s102 1000 mock-user - pts/1\n", {
        {"s102", "Service=sshd\nRemote=yes\nName=mock-user\nRemoteHost=" + ip + "\n"}
    });
    expect(second.size() == 1 && second.first().id == "s102", "Reconnected session detected");
}

void testFormatting() {
    expect(humanRate(std::nullopt) == "N/A", "Unknown rate formatting");
    expect(humanRate(0.0) == "0 B/s", "Zero rate formatting");
    expect(humanRate(1024.0) == "1.0 KiB/s", "KiB/s rate formatting");
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    testIpParsing();
    testSessionParsing();
    testSocketParsing();
    testThroughput();
    testFormatting();
    testReconnectSessions();
    qInfo() << "All synthetic monitoring tests passed.";
    return EXIT_SUCCESS;
}
