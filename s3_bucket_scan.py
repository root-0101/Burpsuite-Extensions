from burp import IBurpExtender, ITab, IContextMenuFactory, IScannerCheck, IScanIssue
from javax.swing import (
    JPanel, JScrollPane, JTable, JButton, JFileChooser,
    JMenuItem, JOptionPane, JTextArea, JSplitPane,
    JProgressBar, JLabel, JTextField, Box
)
from javax.swing.event import DocumentListener
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.awt import BorderLayout, Dimension, FlowLayout
from java.util import ArrayList
import re
import datetime
import time
import threading


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Cloud Bucket & Leak Scanner")

        self.buckets = set()
        self.counter = 0

        # ================= POWERFUL MULTI-CLOUD REGEX =================
        # S3 Patterns
        self.s3_regex = re.compile(
            r'(?:'
            r'(?P<s3_vh>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:-control)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?'
            r'|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?/(?P<s3_ps>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])'
            r'|s3://(?P<s3_uri>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])'
            r'|(?P<s3_web>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-website(?:[.-][a-z0-9-]+)?\.amazonaws\.com'
            r')', re.IGNORECASE
        )

        # Azure Patterns
        self.azure_regex = re.compile(
            r'(?:'
            r'(?P<az_blob>[a-z0-9]{3,24})\.(?:blob|file|table|queue|dfs)\.core\.windows\.net'
            r'|(?P<az_web>[a-z0-9]{3,24})\.z[0-9]+\.web\.core\.windows\.net'
            r')', re.IGNORECASE
        )

        # GCP Patterns
        self.gcp_regex = re.compile(
            r'(?:'
            r'(?P<gcp_vh>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.storage\.googleapis\.com'
            r'|storage\.googleapis\.com/(?P<gcp_ps>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])'
            r'|gs://(?P<gcp_uri>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])'
            r')', re.IGNORECASE
        )


        # ================= UI =================
        self.main_panel = JPanel(BorderLayout())

        # Top Control Panel
        top_panel = JPanel(BorderLayout())
        search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        search_panel.add(JLabel("Filter:"))
        self.search_field = JTextField(20)
        self.search_field.getDocument().addDocumentListener(self.SearchListener(self))
        search_panel.add(self.search_field)
        top_panel.add(search_panel, BorderLayout.WEST)
        
        self.main_panel.add(top_panel, BorderLayout.NORTH)

        self.table_model = DefaultTableModel(
            ["#", "Provider", "Asset Name", "Type", "Source URL"], 0
        )
        self.table = JTable(self.table_model)
        self.sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.sorter)

        self.log_area = JTextArea()
        self.log_area.setEditable(False)

        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self.table),
            JScrollPane(self.log_area)
        )
        split.setDividerLocation(400)

        self.main_panel.add(split, BorderLayout.CENTER)

        # ---- Bottom Panel ----
        bottom = JPanel(BorderLayout())

        self.progress = JProgressBar(0, 100)
        self.progress.setStringPainted(True)
        self.progress.setPreferredSize(Dimension(0, 18))

        self.progress_label = JLabel("Status: Idle")

        bottom.add(self.progress, BorderLayout.CENTER)
        
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        status_panel.add(self.progress_label)
        bottom.add(status_panel, BorderLayout.SOUTH)

        buttons = JPanel(FlowLayout(FlowLayout.RIGHT))

        copy_btn = JButton("Copy Selection")
        copy_btn.addActionListener(self.copyBuckets)
        buttons.add(copy_btn)

        export_btn = JButton("Export CSV")
        export_btn.addActionListener(self.exportBuckets)
        buttons.add(export_btn)

        clear_btn = JButton("Clear All")
        clear_btn.addActionListener(self.clearData)
        buttons.add(clear_btn)

        bottom.add(buttons, BorderLayout.NORTH)

        self.main_panel.add(bottom, BorderLayout.SOUTH)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)

        self.log("Cloud Scanner Loaded Successfully")

    class SearchListener(DocumentListener):
        def __init__(self, extender):
            self.extender = extender
        def insertUpdate(self, e): self.filter()
        def removeUpdate(self, e): self.filter()
        def changedUpdate(self, e): self.filter()
        def filter(self):
            text = self.extender.search_field.getText()
            if not text:
                self.extender.sorter.setRowFilter(None)
            else:
                self.extender.sorter.setRowFilter(re.compile(text, re.IGNORECASE))

    # ================= TAB =================
    def getTabCaption(self):
        return "Cloud Scanner"

    def getUiComponent(self):
        return self.main_panel

    # ================= CONTEXT MENU =================
    def createMenuItems(self, invocation):
        return [JMenuItem(
            "Send to Cloud Scanner",
            actionPerformed=lambda x: threading.Thread(target=self.processMessages, args=(invocation,)).start()
        )]

    # ================= SCANNER CHECK =================
    def doPassiveScan(self, baseRequestResponse):
        # Scan URL, Request, and Response
        url = self.helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        
        # Request
        req = baseRequestResponse.getRequest()
        if req:
            info = self.helpers.analyzeRequest(req)
            body = self.helpers.bytesToString(req[info.getBodyOffset():])
            self.extractAssets(body, url)

        # Response
        resp = baseRequestResponse.getResponse()
        if resp:
            info = self.helpers.analyzeResponse(resp)
            body = self.helpers.bytesToString(resp[info.getBodyOffset():])
            self.extractAssets(body, url)
            
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1

    # ================= CORE =================
    def processMessages(self, invocation):
        messages = invocation.getSelectedMessages()
        total = len(messages)
        if total == 0: return

        self.progress.setValue(0)
        self.progress_label.setText("Status: Scanning %d messages..." % total)
        
        start = time.time()
        for i, msg in enumerate(messages, start=1):
            self.scanMessage(msg)
            pct = int((float(i) / total) * 100)
            self.progress.setValue(pct)
            
        self.progress_label.setText("Status: Scan Completed")
        self.log("Bulk scan finished: %d items processed" % total)

    def scanMessage(self, message):
        try:
            url = self.helpers.analyzeRequest(message).getUrl().toString()
            
            # Request
            req = message.getRequest()
            if req:
                info = self.helpers.analyzeRequest(req)
                body = self.helpers.bytesToString(req[info.getBodyOffset():])
                self.extractAssets(body, url)

            # Response
            resp = message.getResponse()
            if resp:
                info = self.helpers.analyzeResponse(resp)
                body = self.helpers.bytesToString(resp[info.getBodyOffset():])
                self.extractAssets(body, url)

        except Exception as e:
            self.log("Scan Error: %s" % str(e))

    # ================= EXTRACTION =================
    def extractAssets(self, text, source_url):
        # S3 Extraction
        for m in self.s3_regex.finditer(text):
            name = m.group('s3_vh') or m.group('s3_ps') or m.group('s3_uri') or m.group('s3_web')
            self.addEntry("AWS (S3)", name.lower(), "Bucket", source_url)

        # Azure Extraction
        for m in self.azure_regex.finditer(text):
            name = m.group('az_blob') or m.group('az_web')
            self.addEntry("Azure", name.lower(), "Storage/Web", source_url)

        # GCP Extraction
        for m in self.gcp_regex.finditer(text):
            name = m.group('gcp_vh') or m.group('gcp_ps') or m.group('gcp_uri')
            self.addEntry("GCP", name.lower(), "Bucket", source_url)


    def addEntry(self, provider, name, asset_type, source):
        key = "%s|%s|%s" % (provider, name, source)
        if key not in self.buckets:
            self.buckets.add(key)
            self.counter += 1
            
            from javax.swing import SwingUtilities
            def update_ui():
                self.table_model.addRow([
                    self.counter,
                    provider,
                    name,
                    asset_type,
                    source
                ])
                self.log("[%s] Found %s: %s" % (provider, asset_type, name))
            
            SwingUtilities.invokeLater(update_ui)

    def clearData(self, event):
        self.buckets.clear()
        self.counter = 0
        self.table_model.setRowCount(0)
        self.log_area.setText("")
        self.log("Data cleared")

    # ================= LOGGING =================
    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_area.append("[%s] %s\n" % (ts, msg))
        self.log_area.setCaretPosition(self.log_area.getDocument().getLength())

    # ================= ACTIONS =================
    def copyBuckets(self, event):
        rows = self.table.getSelectedRows()
        if not rows:
            JOptionPane.showMessageDialog(None, "Please select rows to copy")
            return

        output = []
        for row in rows:
            model_row = self.table.convertRowIndexToModel(row)
            line = []
            for col in range(self.table_model.getColumnCount()):
                line.append(str(self.table_model.getValueAt(model_row, col)))
            output.append("\t".join(line))

        self.callbacks.copyToClipboard("\n".join(output))
        self.log("Copied %d rows to clipboard" % len(rows))

    def exportBuckets(self, event):
        if self.table_model.getRowCount() == 0:
            JOptionPane.showMessageDialog(None, "No data to export")
            return

        chooser = JFileChooser()
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            path = f.getAbsolutePath()
            if not path.endswith(".csv"): path += ".csv"
            
            with open(path, "w") as out:
                out.write("ID,Provider,Asset,Type,Source\n")
                for i in range(self.table_model.getRowCount()):
                    line = []
                    for col in range(self.table_model.getColumnCount()):
                        val = str(self.table_model.getValueAt(i, col)).replace(",", ";")
                        line.append(val)
                    out.write(",".join(line) + "\n")
            self.log("Exported data to %s" % path)
