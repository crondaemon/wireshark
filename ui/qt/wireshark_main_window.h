/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_MAIN_WINDOW_H
#define WIRESHARK_MAIN_WINDOW_H

/** @defgroup main_window_group Main window
 * The main window has the following submodules:
   @dot
  digraph main_dependencies {
      node [shape=record, fontname=Helvetica, fontsize=10];
      main [ label="main window" URL="\ref main.h"];
      menu [ label="menubar" URL="\ref menus.h"];
      toolbar [ label="toolbar" URL="\ref main_toolbar.h"];
      packet_list [ label="packet list pane" URL="\ref packet_list.h"];
      proto_draw [ label="packet details & bytes panes" URL="\ref main_proto_draw.h"];
      recent [ label="recent user settings" URL="\ref recent.h"];
      main -> menu [ arrowhead="open", style="solid" ];
      main -> toolbar [ arrowhead="open", style="solid" ];
      main -> packet_list [ arrowhead="open", style="solid" ];
      main -> proto_draw [ arrowhead="open", style="solid" ];
      main -> recent [ arrowhead="open", style="solid" ];
  }
  @enddot
 */

/** @file
 *  The Wireshark main window
 *  @ingroup main_window_group
 *  @ingroup windows_group
 */

#include <stdio.h>

#include <config.h>

#include "ui/ws_ui_util.h"
#include "ui/iface_toolbar.h"
#ifdef HAVE_LIBPCAP
#include "ui/capture_opts.h"
#endif

#include <epan/plugin_if.h>
#include <epan/timestamp.h>

#include <capture/capture_session.h>

#include <QMainWindow>
#include <QPointer>

#ifdef _WIN32
# include <QTimer>
#else
# include <QSocketNotifier>
#endif

#include "capture_file_dialog.h"
#include "capture_file_properties_dialog.h"
#include <ui/qt/utils/field_information.h>
#include <ui/qt/widgets/display_filter_combo.h>
#include "main_window.h"
#include "rtp_stream_dialog.h"
#include "rtp_analysis_dialog.h"
#include "tlskeylog_launcher_dialog.h"

class AccordionFrame;
class DataSourceTab;
class CaptureOptionsDialog;
class PrintDialog;
class FileSetDialog;
class FilterDialog;
class FunnelStatistics;
class WelcomePage;
class PacketCommentDialog;
class PacketDiagram;
class PacketList;
class ProtoTree;
#if defined(HAVE_LIBNL) && defined(HAVE_NL80211)
class WirelessFrame;
#endif
class FilterExpressionToolBar;
class WiresharkApplication;

class QAction;
class QActionGroup;

namespace Ui {
    class WiresharkMainWindow;
}

Q_DECLARE_METATYPE(ts_type)
Q_DECLARE_METATYPE(ts_precision)

class WiresharkMainWindow : public MainWindow
{
    Q_OBJECT

public:
    explicit WiresharkMainWindow(QWidget *parent = nullptr);
    ~WiresharkMainWindow();

#ifdef HAVE_LIBPCAP
    capture_session *captureSession() { return &cap_session_; }
    info_data_t *captureInfoData() { return &info_data_; }
#endif

    virtual QMenu *createPopupMenu();

    CaptureFile *captureFile() { return &capture_file_; }

    void removeAdditionalToolbar(QString toolbarName);

    void addInterfaceToolbar(const iface_toolbar *toolbar_entry);
    void removeInterfaceToolbar(const char *menu_title);

    QString getMwFileName();
    void setMwFileName(QString fileName);

protected:
    virtual bool eventFilter(QObject *obj, QEvent *event);
    virtual bool event(QEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);
    virtual void closeEvent(QCloseEvent *event);
    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event);
    virtual void changeEvent(QEvent* event);

private:
    // XXX Move to FilterUtils
    enum MatchSelected {
        MatchSelectedReplace,
        MatchSelectedAnd,
        MatchSelectedOr,
        MatchSelectedNot,
        MatchSelectedAndNot,
        MatchSelectedOrNot
    };

    enum FileCloseContext {
        Default,
        Quit,
        Restart,
        Reload,
        Update
    };

    Ui::WiresharkMainWindow *main_ui_;
    QFont mono_font_;
#if defined(HAVE_LIBNL) && defined(HAVE_NL80211)
    WirelessFrame *wireless_frame_;
#endif
    QWidget *previous_focus_;
    FileSetDialog *file_set_dialog_;
    QActionGroup *show_hide_actions_;
    QActionGroup *time_display_actions_;
    QActionGroup *time_precision_actions_;
    FunnelStatistics *funnel_statistics_;
    QList<QPair<QAction *, bool> > freeze_actions_;
    QPointer<QWidget> freeze_focus_;
    QMap<QAction *, ts_type> td_actions;
    QMap<QAction *, ts_precision> tp_actions;
    bool was_maximized_;

    /* the following values are maintained so that the capture file name and status
    is available when there is no cf structure available */
    QString mwFileName_;

    bool capture_stopping_;
    bool capture_filter_valid_;
#ifdef HAVE_LIBPCAP
    capture_session cap_session_;
    CaptureOptionsDialog *capture_options_dialog_;
    info_data_t info_data_;
#endif

#if defined(Q_OS_MAC)
    QMenu *dock_menu_;
#endif

#ifdef HAVE_SOFTWARE_UPDATE
    QAction *update_action_;
#endif

    QPoint dragStartPosition;

    QPointer<TLSKeylogDialog> tlskeylog_dialog_;

    void freeze();
    void thaw();

    void mergeCaptureFile();
    void importCaptureFile();
    bool saveCaptureFile(capture_file *cf, bool dont_reopen);
    bool saveAsCaptureFile(capture_file *cf, bool must_support_comments = false, bool dont_reopen = false);
    void exportSelectedPackets();
    void exportDissections(export_type_e export_type);

#ifdef Q_OS_WIN
    void fileAddExtension(QString &file_name, int file_type, wtap_compression_type compression_type);
#endif // Q_OS_WIN
    bool testCaptureFileClose(QString before_what, FileCloseContext context = Default);
    void captureStop(bool discard = false);

    void initMainToolbarIcons();
    void initShowHideMainWidgets();
    void initTimeDisplayFormatMenu();
    void initTimePrecisionFormatMenu();
    void initFreezeActions();

    void setMenusForCaptureFile(bool force_disable = false);
    void setMenusForCaptureInProgress(bool capture_in_progress = false);
    void setMenusForCaptureStopping();
    void setForCapturedPackets(bool have_captured_packets);
    void setMenusForFileSet(bool enable_list_files);
    void setWindowIcon(const QIcon &icon);
    void updateStyleSheet();

    void externalMenuHelper(ext_menu_t * menu, QMenu  * subMenu, int depth);

    void setForCaptureInProgress(bool capture_in_progress = false, bool handle_toolbars = false, GArray *ifaces = NULL);
    QMenu* findOrAddMenu(QMenu *parent_menu, const QStringList& menu_parts);
    QMenu* findOrAddMenubar(const QString menu_text);

    void captureFileReadStarted(const QString &action);

    void addMenusandSubmenus(QAction *action, QMenu *cur_menu);
    void removeMenusandSubmenus(QAction *action, QMenu *cur_menu);
    void addMenuActions(QList<QAction *> &actions, int menu_group);
    void removeMenuActions(QList<QAction *> &actions, int menu_group);
    void goToConversationFrame(bool go_next, bool start_current = true);
    void colorizeWithFilter(QByteArray filter, int color_number = -1);

signals:
    void setDissectedCaptureFile(capture_file *cf);
    void closePacketDialogs();
    void reloadFields();
    void packetInfoChanged(struct _packet_info *pinfo);
    void fieldFilterChanged(const QByteArray field_filter);

    void selectRtpStream(rtpstream_id_t *id);
    void deselectRtpStream(rtpstream_id_t *id);

#ifdef HAVE_LIBPCAP
    void showExtcapOptions(QString &device_name, bool startCaptureOnClose);
#endif

public slots:
    // Qt lets you connect signals and slots using functors (new, manual style)
    // and strings (old style). Functors are preferred since they're connected at
    // compile time and less error prone.
    //
    // If you're manually connecting a signal to a slot, don't prefix its name
    // with "on_". Otherwise Qt will try to automatically connect it and you'll
    // get runtime warnings.

    // in main_window_slots.cpp
    /**
     * Open a capture file.
     * @param cf_path Path to the file.
     * @param display_filter Display filter to apply. May be empty.
     * @param type File type.
     * @param is_tempfile true/false.
     * @return True on success, false on failure.
     */
    // XXX We might want to return a cf_read_status_t or a CaptureFile.
    bool openCaptureFile(QString cf_path, QString display_filter, unsigned int type, bool is_tempfile = false);
    bool openCaptureFile(QString cf_path = QString(), QString display_filter = QString()) { return openCaptureFile(cf_path, display_filter, WTAP_TYPE_AUTO); }
    void filterPackets(QString new_filter = QString(), bool force = false);
    void layoutToolbars();
    void updatePreferenceActions();
    void updateRecentActions();

    void setTitlebarForCaptureFile();

    void showCaptureOptionsDialog();

#ifdef HAVE_LIBPCAP
    void captureCapturePrepared(capture_session *);
    void captureCaptureUpdateStarted(capture_session *);
    void captureCaptureUpdateFinished(capture_session *);
    void captureCaptureFixedFinished(capture_session *cap_session);
    void captureCaptureFailed(capture_session *);
#endif

    void captureFileOpened();
    void captureFileReadFinished();
    void captureFileClosing();
    void captureFileClosed();

    void launchRLCGraph(bool channelKnown, uint8_t RAT, uint16_t ueid, uint8_t rlcMode,
                        uint16_t channelType, uint16_t channelId, uint8_t direction);

    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

private slots:

    void captureEventHandler(CaptureEvent ev);

    void initViewColorizeMenu();
    void initConversationMenus();
    static bool addExportObjectsMenuItem(const void *key, void *value, void *userdata);
    void initExportObjectsMenus();
    static bool addFollowStreamMenuItem(const void *key, void *value, void *userdata);
    void initFollowStreamMenus();

    // in main_window_slots.cpp
    /**
     * @brief startCapture
     * Start capturing from the selected interfaces using the capture filter
     * shown in the main welcome screen.
     */
    void startCapture(QStringList);
    void startCapture();
    void pushLiveCaptureInProgress();
    void popLiveCaptureInProgress();
    void stopCapture();

    void loadWindowGeometry();
    void saveWindowGeometry();
    void mainStackChanged(int);
    void updateRecentCaptures();
    void recentActionTriggered();
    void addPacketComment();
    void editPacketComment();
    void deletePacketComment();
    void deleteCommentsFromPackets();
    QString commentToMenuText(QString text, int max_len = 40);
    void setEditCommentsMenu();
    void setMenusForSelectedPacket();
    void setMenusForSelectedTreeRow(FieldInformation *fi = NULL);
    void interfaceSelectionChanged();
    void captureFilterSyntaxChanged(bool valid);
    void redissectPackets();
    void checkDisplayFilter();
    void fieldsChanged();
    void reloadLuaPlugins();
    void showAccordionFrame(AccordionFrame *show_frame, bool toggle = false);
    void showColumnEditor(int column);
    void showPreferenceEditor(); // module_t *, pref *
    void addStatsPluginsToMenu();
    void addDynamicMenus();
    void reloadDynamicMenus();
    void addPluginIFStructures();
    QMenu * searchSubMenu(QString objectName);
    void activatePluginIFToolbar(bool);

    void startInterfaceCapture(bool valid, const QString capture_filter);

    void applyGlobalCommandLineOptions();
    void setFeaturesEnabled(bool enabled = true);

    void on_actionNewDisplayFilterExpression_triggered();
    void onFilterSelected(QString, bool);
    void onFilterPreferences();
    void onFilterEdit(int uatIndex);

    // Handle FilterAction signals
    void queuedFilterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /** Pass stat cmd arguments to a slot.
     * @param menu_path slot Partial slot name, e.g. "StatisticsIOGraph".
     * @param arg "-z" argument, e.g. "io,stat".
     * @param userdata Optional user data.
     */
    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);

    /** Pass tap parameter arguments to a slot.
     * @param cfg_str slot Partial slot name, e.g. "StatisticsAFPSrt".
     * @param arg "-z" argument, e.g. "afp,srt".
     * @param userdata Optional user data.
     */
    void openTapParameterDialog(const QString cfg_str, const QString arg, void *userdata);
    void openTapParameterDialog();

#if defined(HAVE_SOFTWARE_UPDATE) && defined(Q_OS_WIN)
    void softwareUpdateRequested();
#endif

    // If you're manually connecting a signal to a slot, don't prefix its name
    // with "on_". Otherwise you'll get runtime warnings.

    void connectFileMenuActions();
    void exportPacketBytes();
    void exportPDU();
    void stripPacketHeaders();
    void exportTLSSessionKeys();
    void printFile();

    void connectEditMenuActions();
    void copySelectedItems(WiresharkMainWindow::CopySelected selection_type);
    void findPacket();
    void editTimeShift();
    void editConfigurationProfiles();
    void editTimeShiftFinished(int);
    void addPacketCommentFinished(PacketCommentDialog* pc_dialog, int result);
    void editPacketCommentFinished(PacketCommentDialog* pc_dialog, int result, unsigned nComment);
    void deleteAllPacketComments();
    void deleteAllPacketCommentsFinished(int result);
    void injectSecrets();
    void discardAllSecrets();
    void discardAllSecretsFinished(int result);
    void showPreferencesDialog(QString module_name);

    void connectViewMenuActions();
    void showHideMainWidgets(QAction *action);
    void setTimestampFormat(QAction *action);
    void setTimestampPrecision(QAction *action);
    void setTimeDisplaySecondsWithHoursAndMinutes(bool checked);
    void editResolvedName();
    void setNameResolution();
    void zoomText();
    void showColoringRulesDialog();
    void colorizeConversation(bool create_rule = false);
    void colorizeActionTriggered();
    void openPacketDialog(bool from_reference = false);
    void reloadCaptureFileAsFormatOrCapture();
    void reloadCaptureFile();

    void connectGoMenuActions();

    void setPreviousFocus();
    void resetPreviousFocus();

    void connectCaptureMenuActions();
    void startCaptureTriggered();

    void connectAnalyzeMenuActions();

    void matchFieldFilter(FilterAction::Action action, FilterAction::ActionType filter_type);
    void applyFieldAsColumn();

    void filterMenuAboutToShow();

    void applyConversationFilter();
    void applyExportObject();

    void openFollowStreamDialog(int proto_id, unsigned stream_num, unsigned sub_stream_num, bool use_stream_index = true);
    void openFollowStreamDialog(int proto_id);
    void openIOGraph(bool filtered, QVector<uint> conv_ids, QVector<QVariant> conv_agg);

    void statCommandExpertInfo(const char *, void *);

    void connectHelpMenuActions();

#ifdef HAVE_SOFTWARE_UPDATE
    void checkForUpdates();
#endif

    void goToCancelClicked();
    void goToGoClicked();
    void goToLineEditReturnPressed();

    void connectStatisticsMenuActions();

    void showResolvedAddressesDialog();
    void showConversationsDialog();
    void showEndpointsDialog();

    void openTcpStreamDialog(int graph_type);
    void openSCTPAllAssocsDialog();
    void on_actionSCTPShowAllAssociations_triggered();
    void on_actionSCTPAnalyseThisAssociation_triggered();
    void on_actionSCTPFilterThisAssociation_triggered();
    void statCommandMulticastStatistics(const char *arg, void *);

    void statCommandWlanStatistics(const char *arg, void *);

    void openStatisticsTreeDialog(const char *abbr);
    void statCommandIOGraph(const char *, void *);
    void showIOGraphDialog(io_graph_item_unit_t value_units, QString);

    void showPlotDialog(const QString& y_field = QString(), bool filtered = false);

    void connectTelephonyMenuActions();

    RtpStreamDialog *openTelephonyRtpStreamsDialog();
    RtpPlayerDialog *openTelephonyRtpPlayerDialog();
    RtpAnalysisDialog *openTelephonyRtpAnalysisDialog();
    void statCommandLteMacStatistics(const char *arg, void *);
    void statCommandLteRlcStatistics(const char *arg, void *);
    void openRtpStreamAnalysisDialog();
    void openRtpPlayerDialog();

    void connectWirelessMenuActions();

    void connectToolsMenuActions();

    void externalMenuItemTriggered();

    void on_actionContextWikiProtocolPage_triggered();
    void on_actionContextFilterFieldReference_triggered();

    void extcap_options_finished(int result);
    void showExtcapOptionsDialog(QString & device_name, bool startCaptureOnClose);

    QString findRtpStreams(QVector<rtpstream_id_t *> *stream_ids, bool reverse);

    void openTLSKeylogDialog();

    friend class MainApplication;
};

#endif // WIRESHARK_MAIN_WINDOW_H
