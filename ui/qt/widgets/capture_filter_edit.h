/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_EDIT_H
#define CAPTURE_FILTER_EDIT_H

#include <QThread>
#include <QToolButton>
#include <QActionGroup>

#include <ui/qt/widgets/syntax_line_edit.h>

class CaptureFilterSyntaxWorker;
class StockIconToolButton;

class CaptureFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit CaptureFilterEdit(QWidget *parent = 0, bool plain = false);
    ~CaptureFilterEdit();
    void setConflict(bool conflict = false);
    // No selections: (QString(), false)
    // Selections, same filter: (filter, false)
    // Selections, different filters (QString(), true)
    static QPair<const QString, bool> getSelectedFilter();

protected:
    void paintEvent(QPaintEvent *evt);
    void resizeEvent(QResizeEvent *);
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

public slots:
    void checkFilter();
    void updateBookmarkMenu();
    void saveFilter();
    void removeFilter();
    void showFilters();
    void prepareFilter();

private slots:
    void applyCaptureFilter();
    void checkFilter(const QString &filter);
    void setFilterSyntaxState(QString filter, int state, QString err_msg);
    void bookmarkClicked();
    void clearFilter();

private:
    void updateFilter();

    bool plain_;
    bool field_name_only_;
    bool enable_save_action_;
    QString placeholder_text_;
    QAction *save_action_;
    QAction *remove_action_;
    QActionGroup * actions_;
    StockIconToolButton *bookmark_button_;
    StockIconToolButton *clear_button_;
    StockIconToolButton *apply_button_;
    CaptureFilterSyntaxWorker *syntax_worker_;
    QThread *syntax_thread_;
    QTimer *line_edit_timer_;

    void buildCompletionList(const QString &primitive_word, const QString &preamble);

signals:
    void captureFilterSyntaxChanged(bool valid);
    void captureFilterChanged(const QString filter);
    void startCapture();
    void addBookmark(const QString filter);

};

#endif // CAPTURE_FILTER_EDIT_H
