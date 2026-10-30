// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QHash>
#include <QList>
#include <QString>
#include <QMetaType>
#include <chrono>
#include <optional>

struct Session {
    QString id, user, host, tty, since, state;
};

struct Socket {
    QString host, remotePort, localPort;
    std::optional<quint64> sent, received;
    QString key() const { return host + QChar(0) + remotePort + QChar(0) + localPort; }
};

struct Snapshot {
    QList<Session> sessions;
    QList<Socket> sockets;
    std::chrono::steady_clock::time_point timestamp;
    QString error, trafficError;
};
Q_DECLARE_METATYPE(Snapshot)

struct Rate {
    std::optional<double> up, down;
};

QString normalizeIp(QString host);
QPair<QString, QString> splitEndpoint(const QString &value);
QList<Session> parseSessions(const QString &table, const QHash<QString, QString> &details);
QList<Socket> parseSockets(const QString &output);
QString humanRate(std::optional<double> value);
QString runCommand(const QString &program, const QStringList &arguments, QString *error);
Snapshot gather(int port);

class Throughput {
public:
    QHash<QString, Rate> calculate(const Snapshot &snapshot);
private:
    QHash<QString, Socket> previous_;
    std::optional<std::chrono::steady_clock::time_point> last_;
};
