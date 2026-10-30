// SPDX-License-Identifier: GPL-3.0-or-later
#include "monitor.h"

#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStringList>
#include <arpa/inet.h>
#include <cstring>
#include <cmath>

QString normalizeIp(QString host) {
    host = host.trimmed();
    if (host.startsWith('[') && host.endsWith(']')) host = host.mid(1, host.size() - 2);
    host = host.section('%', 0, 0);
    const QByteArray raw = host.toUtf8();
    char buffer[INET6_ADDRSTRLEN];
    in_addr ipv4{};
    if (inet_pton(AF_INET, raw.constData(), &ipv4) == 1) {
        inet_ntop(AF_INET, &ipv4, buffer, sizeof(buffer));
        return QString::fromLatin1(buffer);
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, raw.constData(), &ipv6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
            std::memcpy(&ipv4, &ipv6.s6_addr[12], 4);
            inet_ntop(AF_INET, &ipv4, buffer, sizeof(buffer));
        } else {
            inet_ntop(AF_INET6, &ipv6, buffer, sizeof(buffer));
        }
        return QString::fromLatin1(buffer);
    }
    return host.toLower();
}

QPair<QString, QString> splitEndpoint(const QString &value) {
    const int colon = value.lastIndexOf(':');
    if (colon < 0) return {normalizeIp(value), {}};
    return {normalizeIp(value.left(colon)), value.mid(colon + 1)};
}

static QHash<QString, QString> parseProperties(const QString &source) {
    QHash<QString, QString> values;
    for (const QString &line : source.split('\n')) {
        const int eq = line.indexOf('=');
        if (eq > 0) values.insert(line.left(eq), line.mid(eq + 1));
    }
    return values;
}

QList<Session> parseSessions(const QString &table, const QHash<QString, QString> &details) {
    QList<Session> sessions;
    for (const QString &line : table.split('\n')) {
        const QStringList fields = line.simplified().split(' ', Qt::SkipEmptyParts);
        if (fields.isEmpty()) continue;
        const QString id = fields.first();
        const auto props = parseProperties(details.value(id));
        if (props.value("Service") != "sshd" || props.value("Remote").toLower() != "yes") continue;
        sessions.append({id, props.value("Name", "unknown"),
                         normalizeIp(props.value("RemoteHost", "unknown")),
                         props.value("TTY"), props.value("Timestamp"), props.value("State")});
    }
    return sessions;
}

QList<Socket> parseSockets(const QString &output) {
    QList<Socket> sockets;
    std::optional<Socket> current;
    static const QRegularExpression sentRe(R"(\bbytes_sent:(\d+)\b)");
    static const QRegularExpression receivedRe(R"(\bbytes_received:(\d+)\b)");
    auto flush = [&] {
        if (current) sockets.append(*current);
        current.reset();
    };
    for (const QString &line : output.split('\n')) {
        if (line.trimmed().isEmpty()) continue;
        // Each socket begins on a non-indented row; indented rows contain TCP metrics.
        if (!line.at(0).isSpace()) {
            flush();
            const QStringList fields = line.simplified().split(' ', Qt::SkipEmptyParts);
            int offset = 0;
            if (!fields.isEmpty() && (fields[0] == "ESTAB" || fields[0] == "ESTABLISHED" || fields[0] == "tcp")) offset = 1;
            if (fields.size() < offset + 4) continue;
            const auto local = splitEndpoint(fields.at(offset + 2));
            const auto remote = splitEndpoint(fields.at(offset + 3));
            current = Socket{remote.first, remote.second, local.second, {}, {}};
        } else if (current) {
            const auto sentMatch = sentRe.match(line);
            const auto recvMatch = receivedRe.match(line);
            if (sentMatch.hasMatch()) current->sent = sentMatch.captured(1).toULongLong();
            if (recvMatch.hasMatch()) current->received = recvMatch.captured(1).toULongLong();
        }
    }
    flush();
    return sockets;
}

QString runCommand(const QString &program, const QStringList &arguments, QString *error) {
    QProcess process;
    auto env = QProcessEnvironment::systemEnvironment();
    env.insert("LC_ALL", "C");
    process.setProcessEnvironment(env);
    process.start(program, arguments);
    if (!process.waitForStarted(1500)) {
        if (error) *error = process.errorString();
        return {};
    }
    if (!process.waitForFinished(3000)) {
        process.kill();
        process.waitForFinished(1000);
        if (error) *error = "Command timed out: " + program;
        return {};
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (error) {
            *error = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
            if (error->isEmpty()) *error = program + " exited with an error";
        }
        return {};
    }
    return QString::fromLocal8Bit(process.readAllStandardOutput());
}

Snapshot gather(int port) {
    Snapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    QString error;
    const QString listing = runCommand("loginctl", {"list-sessions", "--no-legend", "--no-pager"}, &error);
    if (!error.isEmpty()) {
        snapshot.error = "Cannot list sessions: " + error;
        return snapshot;
    }
    QHash<QString, QString> details;
    for (const QString &line : listing.split('\n')) {
        const QStringList fields = line.simplified().split(' ', Qt::SkipEmptyParts);
        if (fields.isEmpty()) continue;
        const QString &id = fields.first();
        QString detailError;
        const QString detail = runCommand("loginctl", {"show-session", id, "--no-pager"}, &detailError);
        // A session can disappear between list-sessions and show-session.
        if (!detailError.isEmpty()) continue;
        details.insert(id, detail);
    }
    snapshot.sessions = parseSessions(listing, details);
    if (!snapshot.sessions.isEmpty()) {
        const QString filter = QString("( sport = :%1 )").arg(port);
        const QString output = runCommand("ss", {"-Htin", "state", "established", filter}, &snapshot.trafficError);
        if (snapshot.trafficError.isEmpty()) snapshot.sockets = parseSockets(output);
    }
    snapshot.timestamp = std::chrono::steady_clock::now();
    return snapshot;
}

QHash<QString, Rate> Throughput::calculate(const Snapshot &snapshot) {
    QHash<QString, Rate> result;
    QHash<QString, Socket> next;
    const double interval = last_ ? std::chrono::duration<double>(snapshot.timestamp - *last_).count() : 0.0;
    for (const Socket &socket : snapshot.sockets) {
        const QString key = socket.key();
        std::optional<double> up, down;
        if (interval > 0.0 && previous_.contains(key)) {
            const Socket &old = previous_.value(key);
            if (old.sent && socket.sent) up = static_cast<double>(*socket.sent >= *old.sent ? *socket.sent - *old.sent : 0) / interval;
            if (old.received && socket.received) down = static_cast<double>(*socket.received >= *old.received ? *socket.received - *old.received : 0) / interval;
        }
        if (result.contains(socket.host)) {
            const auto old = result.value(socket.host);
            up = old.up && up ? std::optional<double>(*old.up + *up) : std::nullopt;
            down = old.down && down ? std::optional<double>(*old.down + *down) : std::nullopt;
        }
        result.insert(socket.host, {up, down});
        next.insert(key, socket);
    }
    previous_ = std::move(next);
    last_ = snapshot.timestamp;
    return result;
}

QString humanRate(std::optional<double> value) {
    if (!value) return "N/A";
    double speed = std::max(0.0, *value);
    const char *units[] = {"B/s", "KiB/s", "MiB/s", "GiB/s"};
    int unit = 0;
    while (speed >= 1024.0 && unit < 3) { speed /= 1024.0; ++unit; }
    return unit == 0 ? QString::number(std::round(speed), 'f', 0) + " " + units[unit]
                     : QString::number(speed, 'f', 1) + " " + units[unit];
}
