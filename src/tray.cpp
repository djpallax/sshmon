// SPDX-License-Identifier: GPL-3.0-or-later
#include "monitor.h"

#include <QApplication>
#include <QColor>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QDir>
#include <QFont>
#include <QIcon>
#include <QLockFile>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QDebug>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <KStatusNotifierItem>
#include <QThread>
#include <QTimer>

#include <algorithm>
#include <memory>
#include <tuple>
#include <unistd.h>

class PollWorker final : public QObject {
    Q_OBJECT
signals:
    void ready(const Snapshot &snapshot);
public:
    void poll(int port) { emit ready(gather(port)); }
};

class TrayMonitor final : public QObject {
    Q_OBJECT
public:
    TrayMonitor(QApplication &app, int port, int intervalMs)
        : QObject(&app), app_(app), port_(port), tray_("sshmon", this), menu_(new QMenu), worker_(new PollWorker) {
        // Keep the D-Bus StatusNotifierItem registered for the whole process lifetime.
        // Toggling Passive/Active avoids unregistration on disconnect/reconnect.
        tray_.setTitle("SSHmon");
        tray_.setCategory(KStatusNotifierItem::Communications);
        tray_.setStandardActionsEnabled(false);
        tray_.setIconByName("link");
        tray_.setToolTip("link", "SSHmon", "No authenticated SSH sessions");
        tray_.setContextMenu(menu_); // KStatusNotifierItem owns menu_.
        tray_.setStatus(KStatusNotifierItem::Passive);
        QObject::connect(menu_, &QMenu::aboutToShow, this, &TrayMonitor::refreshRates);
        QObject::connect(menu_, &QMenu::aboutToHide, this, [this] {
            if (pendingMenu_) QTimer::singleShot(0, this, [this] {
                if (pendingMenu_) rebuildMenu();
            });
        });
        worker_->moveToThread(&workerThread_);
        QObject::connect(&workerThread_, &QThread::finished, worker_, &QObject::deleteLater);
        QObject::connect(worker_, &PollWorker::ready, this, &TrayMonitor::updated, Qt::QueuedConnection);
        workerThread_.start();
        QObject::connect(&timer_, &QTimer::timeout, this, &TrayMonitor::poll);
        timer_.start(intervalMs);
        poll();
    }

    ~TrayMonitor() override {
        timer_.stop();
        tray_.setStatus(KStatusNotifierItem::Passive);
        for (QProcess *p : runningActions_) {
            p->kill();
            p->waitForFinished(1000);
        }
        workerThread_.quit();
        workerThread_.wait();
        // The KStatusNotifierItem owns the context menu.
    }

private:
    struct RateAction { QAction *action; QString host, suffix; };

    static QIcon renderIcon(int count, bool upActive, bool downActive) {
        QPixmap pix(64, 64);
        pix.fill(Qt::transparent);
        QPainter p(&pix);
        p.setRenderHint(QPainter::Antialiasing);
        const QIcon base = QIcon::fromTheme("link");
        if (!base.isNull()) {
            p.drawPixmap(2, 2, 54, 54, base.pixmap(54, 54));
        } else {
            p.setBrush(QColor("#313e51"));
            p.setPen(QColor("#d3dbe7"));
            p.drawRoundedRect(6, 5, 49, 48, 8, 8);
            p.setPen(Qt::white);
            p.setFont(QFont("Sans", 10, QFont::Bold));
            p.drawText(7, 6, 47, 43, Qt::AlignCenter, "SSH");
        }
        for (const auto &indicator : {
                 std::tuple<QString, int, bool, QString>{QString::fromUtf8("↑"), 3, upActive, "#30bf76"},
                 {QString::fromUtf8("↓"), 30, downActive, "#34b6ec"}}) {
            const auto &[symbol, x, active, color] = indicator;
            p.setBrush(QColor(active ? color : "#666e79"));
            p.setPen(QColor("#20252b"));
            p.drawRoundedRect(x, 43, 30, 19, 7, 7);
            p.setPen(Qt::white);
            p.setFont(QFont("Sans", 12, QFont::Bold));
            p.drawText(x, 41, 30, 19, Qt::AlignCenter, symbol);
        }
        p.setBrush(QColor("#d13d52"));
        p.setPen(Qt::white);
        p.drawEllipse(37, 0, 25, 25);
        p.setFont(QFont("Sans", 9, QFont::Bold));
        p.drawText(37, 0, 25, 25, Qt::AlignCenter, count > 9 ? "9+" : QString::number(count));
        p.end();
        return QIcon(pix);
    }

    void poll() {
        if (busy_) return;
        busy_ = true;
        QMetaObject::invokeMethod(worker_, [worker = worker_, port = port_] { worker->poll(port); }, Qt::QueuedConnection);
    }

    QString signature() const {
        QStringList ids;
        for (const Session &s : sessions_) {
            ids.append(s.id + QChar(0) + s.user + QChar(0) + s.host + QChar(0) + s.tty);
        }
        ids.sort();
        return ids.join(QChar(1));
    }

    void updated(const Snapshot &snapshot) {
        busy_ = false;
        if (!snapshot.error.isEmpty()) {
            // Fail visible: never silently report "no SSH" if session discovery fails.
            tray_.setToolTip("dialog-warning", "SSHmon", "Warning: " + snapshot.error);
            tray_.setAttentionIconByName("dialog-warning");
            tray_.setIconByName("dialog-warning");
            tray_.setStatus(KStatusNotifierItem::NeedsAttention);
            if (errorMenu_ != snapshot.error && !menu_->isVisible()) {
                menu_->clear();
                rateActions_.clear();
                auto *err = menu_->addAction(snapshot.error);
                err->setEnabled(false);
                menu_->addAction("Quit monitor", &app_, &QApplication::quit);
            }
            errorMenu_ = snapshot.error;
            iconSignature_ = -1;
            pendingMenu_ = true;
            return;
        }
        sessions_ = snapshot.sessions;
        if (lastLoggedSessionCount_ != sessions_.size()) {
            qInfo().noquote() << "SSHmon: authenticated SSH sessions:" << sessions_.size();
            lastLoggedSessionCount_ = sessions_.size();
        }
        rates_ = throughput_.calculate(snapshot);
        trafficError_ = snapshot.trafficError;
        if (sessions_.isEmpty()) {
            // Passive keeps the item registered with Plasma, but removes it from
            // the normal visible tray area. Reconnect => Active immediately.
            tray_.setStatus(KStatusNotifierItem::Passive);
            menuSignature_.clear();
            errorMenu_.clear();
            iconSignature_ = -1;
            pendingMenu_ = false;
            return;
        }
        const bool recoveredFromError = !errorMenu_.isEmpty();
        errorMenu_.clear();
        if (signature() != menuSignature_ || recoveredFromError) {
            if (menu_->isVisible()) pendingMenu_ = true;
            else rebuildMenu();
        }
        refreshRates();

        double up = 0, down = 0;
        bool known = true;
        QSet<QString> uniqueHosts;
        for (const Session &s : sessions_) uniqueHosts.insert(s.host);
        for (const QString &host : uniqueHosts) {
            const Rate r = rates_.value(host);
            if (!r.up || !r.down) known = false;
            up += r.up.value_or(0);
            down += r.down.value_or(0);
        }
        const int newIconSignature = (std::min(static_cast<int>(sessions_.size()), 10) << 2) | (up > 0 ? 2 : 0) | (down > 0 ? 1 : 0);
        if (newIconSignature != iconSignature_) {
            tray_.setIconByPixmap(renderIcon(sessions_.size(), up > 0, down > 0));
            iconSignature_ = newIconSignature;
        }
        QStringList tooltip;
        tooltip << QString("SSH: %1 authenticated session(s)").arg(sessions_.size());
        tooltip << QString::fromUtf8("↑ Outgoing: ") + humanRate(known ? std::optional<double>(up) : std::nullopt);
        tooltip << QString::fromUtf8("↓ Incoming: ") + humanRate(known ? std::optional<double>(down) : std::nullopt);
        for (int i = 0; i < std::min(5, static_cast<int>(sessions_.size())); ++i) {
            const Session &s = sessions_.at(i);
            tooltip << s.user + "@" + s.host + " (" + s.id + ")";
        }
        if (sessions_.size() > 5) tooltip << QString("...and %1 more").arg(sessions_.size() - 5);
        if (!trafficError_.isEmpty()) tooltip << "Traffic information unavailable";
        tray_.setToolTip("link", "SSHmon", tooltip.join('\n'));
        if (tray_.status() != KStatusNotifierItem::Active)
            tray_.setStatus(KStatusNotifierItem::Active);
    }

    void refreshRates() {
        for (const RateAction &entry : rateActions_) {
            const Rate r = rates_.value(entry.host);
            if (entry.action) {
                const QString text = QString::fromUtf8("↑ ") + humanRate(r.up) +
                                     QString::fromUtf8("    ↓ ") + humanRate(r.down) + entry.suffix;
                if (entry.action->text() != text) entry.action->setText(text);
            }
        }
    }

    void rebuildMenu() {
        if (menu_->isVisible()) { pendingMenu_ = true; return; }
        pendingMenu_ = false;
        menu_->clear();
        rateActions_.clear();
        if (!errorMenu_.isEmpty()) {
            auto *message = menu_->addAction(errorMenu_);
            message->setEnabled(false);
            menu_->addAction("Quit monitor", &app_, &QApplication::quit);
            menuSignature_.clear();
            return;
        }
        menuSignature_ = signature();
        auto *header = menu_->addAction(QString("%1 active SSH session(s)").arg(sessions_.size()));
        header->setEnabled(false);
        if (!trafficError_.isEmpty()) {
            auto *warn = menu_->addAction("Traffic data unavailable");
            warn->setEnabled(false);
        }
        menu_->addSeparator();
        QHash<QString, int> peers;
        for (const Session &s : sessions_) ++peers[s.host];
        for (const Session &s : sessions_) {
            auto *sub = menu_->addMenu(s.user + "  ·  " + s.host + "  [" + s.id + "]");
            QString desc = "Session " + s.id;
            if (!s.state.isEmpty()) desc += " · " + s.state;
            if (!s.tty.isEmpty()) desc += " · " + s.tty;
            auto *label = sub->addAction(desc);
            label->setEnabled(false);
            auto *rate = sub->addAction(QString());
            rate->setEnabled(false);
            rateActions_.append({rate, s.host, peers.value(s.host) > 1 ? " (shared IP)" : ""});
            QObject::connect(sub, &QMenu::aboutToShow, this, &TrayMonitor::refreshRates);
            if (!s.since.isEmpty()) {
                auto *time = sub->addAction(s.since);
                time->setEnabled(false);
            }
            sub->addSeparator();
            sub->addAction("Disconnect this session...", this, [this, s] { disconnectSession(s); });
        }
        menu_->addSeparator();
        menu_->addAction("Stop SSH server", this, &TrayMonitor::stopServer);
        menu_->addSeparator();
        menu_->addAction("Quit monitor", &app_, &QApplication::quit);
        refreshRates();
    }

    static bool sameSession(const Session &s) {
        // ID reuse protection: verify user/host/service at action time.
        static const QRegularExpression validId("^[A-Za-z0-9_-]+$");
        if (!validId.match(s.id).hasMatch()) return false;
        QString error;
        const QString details = runCommand("loginctl", {"show-session", s.id, "--no-pager"}, &error);
        if (!error.isEmpty()) return false;
        const auto validated = parseSessions(s.id + "\n", {{s.id, details}});
        return validated.size() == 1 && validated.at(0).user == s.user &&
               validated.at(0).host == s.host && validated.at(0).since == s.since;
    }

    void disconnectSession(const Session &s) {
        if (!sameSession(s)) {
            QMessageBox::warning(nullptr, "SSHmon", "This session no longer matches the original connection. Refresh the menu.");
            return;
        }
        const QString message = QString("Terminate session %1?\nUser: %2\nRemote host: %3\n\nAll processes belonging to this session will be terminated.")
                                        .arg(s.id, s.user, s.host);
        if (QMessageBox::question(nullptr, "Disconnect SSH session", message,
                                  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
        if (!sameSession(s)) {
            QMessageBox::warning(nullptr, "SSHmon", "The session changed before authorization. Operation cancelled.");
            return;
        }
        privileged("Terminate SSH session", "/usr/bin/loginctl", {"terminate-session", s.id});
    }

    void stopServer() {
        const QString message = "Stop sshd.service?\n\nNew SSH connections will be rejected until it is restarted. "
                                "Existing sessions may remain active. Socket activation, if configured, may still accept connections. "
                                "Make sure you have local or RDP access.";
        if (QMessageBox::question(nullptr, "Stop SSH server", message,
                                  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
            privileged("Stop SSH server", "/usr/bin/systemctl", {"stop", "sshd.service"});
        }
    }

    void privileged(const QString &label, const QString &command, const QStringList &args) {
        auto *proc = new QProcess(this);
        proc->setProcessChannelMode(QProcess::MergedChannels);
        runningActions_.insert(proc);
        const auto completed = std::make_shared<bool>(false);
        const auto cleanup = [this, proc, completed] {
            if (*completed) return false;
            *completed = true;
            runningActions_.remove(proc);
            proc->deleteLater();
            return true;
        };
        QObject::connect(proc, &QProcess::finished, this, [this, proc, label, cleanup](int exitCode, QProcess::ExitStatus status) {
            if (!cleanup()) return;
            const QString output = QString::fromLocal8Bit(proc->readAllStandardOutput()).trimmed();
            if (exitCode != 0 || status != QProcess::NormalExit)
                QMessageBox::warning(nullptr, "SSHmon", label + " failed.\n" +
                                     (output.isEmpty() ? "Authorization denied or cancelled." : output));
            poll();
        });
        QObject::connect(proc, &QProcess::errorOccurred, this, [this, label, cleanup](QProcess::ProcessError error) {
            if (error != QProcess::FailedToStart || !cleanup()) return;
            QMessageBox::warning(nullptr, "SSHmon", "Could not start authorization for: " + label);
        });
        proc->start("/usr/bin/pkexec", QStringList{command} + args);
    }

    QApplication &app_;
    const int port_;
    KStatusNotifierItem tray_;
    QMenu *menu_;
    QThread workerThread_;
    PollWorker *worker_;
    QTimer timer_;
    bool busy_ = false, pendingMenu_ = false;
    int iconSignature_ = -1;
    qsizetype lastLoggedSessionCount_ = -1;
    QString menuSignature_, errorMenu_, trafficError_;
    QList<Session> sessions_;
    QList<RateAction> rateActions_;
    QHash<QString, Rate> rates_;
    Throughput throughput_;
    QSet<QProcess *> runningActions_;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setApplicationName("SSHmon");
    app.setQuitOnLastWindowClosed(false);
    QCommandLineParser parser;
    parser.setApplicationDescription("Lightweight SSH session indicator for KDE Plasma");
    parser.addHelpOption();
    const QCommandLineOption portOption("port", "SSH listening TCP port (default 22)", "port", "22");
    const QCommandLineOption intervalOption("interval", "Polling interval in seconds (default 2)", "seconds", "2");
    parser.addOption(portOption);
    parser.addOption(intervalOption);
    parser.process(app);
    bool okPort = false, okInterval = false;
    const int port = parser.value(portOption).toInt(&okPort);
    const int interval = parser.value(intervalOption).toInt(&okInterval);
    if (!okPort || port < 1 || port > 65535 || !okInterval || interval < 1 || interval > 60)
        parser.showHelp(2);
    QString runtime = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (runtime.isEmpty()) runtime = QDir::tempPath() + QString("/ssh-tray-%1").arg(getuid());
    QDir().mkpath(runtime);
    QLockFile lock(runtime + "/sshmon.lock");
    lock.setStaleLockTime(0);
    if (!lock.tryLock(150)) {
        qCritical("SSHmon is already running.");
        return 1;
    }
    qRegisterMetaType<Snapshot>("Snapshot");
    TrayMonitor monitor(app, port, interval * 1000);
    return app.exec();
}

#include "tray.moc"
