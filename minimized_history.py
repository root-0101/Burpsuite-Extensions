from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from burp import IMessageEditorController
from javax.swing import JPanel, JScrollPane, JTable, JSplitPane, ListSelectionModel, JButton, JMenuItem, JPopupMenu, JLabel, SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Color
from java.awt.event import MouseAdapter
from java.util import ArrayList
from java.lang import StringBuilder
import threading
import time
import base64

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Unified URL Minimizer")
        
        # Data for custom tab
        self._seen_keys = set()
        self._log = []
        self._lock = threading.Lock()
        
        # UI Setup
        self.init_ui()
        
        # Register Context Menu
        callbacks.registerContextMenuFactory(self)
        
        # Add the tab
        callbacks.addSuiteTab(self)
        
        print("Unified URL Minimizer loaded.")
        print("1. Use 'Minimize Native History' to tag duplicates in the main Proxy tab.")
        print("2. Send individual items to the custom tab for manual review.")

    def init_ui(self):
        self._panel = JPanel(BorderLayout())
        
        # Top Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        
        btn_minimize_native = JButton("Minimize Native History", actionPerformed=self.minimize_native_history)
        btn_minimize_native.setBackground(Color(255, 102, 51))
        btn_minimize_native.setForeground(Color.WHITE)
        
        btn_clear_tab = JButton("Clear", actionPerformed=self.clear_custom_tab)
        
        toolbar.add(btn_minimize_native)
        toolbar.add(JLabel(" | "))
        toolbar.add(btn_clear_tab)
        toolbar.add(JLabel(" | "))
        
        self._status_label = JLabel("Ready")
        self._status_label.setForeground(Color.DARK_GRAY)
        toolbar.add(self._status_label)
        
        self._panel.add(toolbar, BorderLayout.NORTH)
        
        # Custom Tab Table Setup
        self._table_model = DefaultTableModel([
            "#", "Host", "Method", "URL", "Params", "Status", "Length", "MIME", "Ext", "Time"
        ], 0)
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._table.setAutoCreateRowSorter(True)
        self._table.addMouseListener(TableMouseListener(self))
        self._table.getSelectionModel().addListSelectionListener(self.row_selected)
        
        scroll_pane = JScrollPane(self._table)
        
        # Split pane
        self._split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._split_pane.setTopComponent(scroll_pane)
        
        # Viewers
        self._request_viewer = self._callbacks.createMessageEditor(self, False)
        self._response_viewer = self._callbacks.createMessageEditor(self, False)
        
        tabs_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        tabs_pane.setLeftComponent(self._request_viewer.getComponent())
        tabs_pane.setRightComponent(self._response_viewer.getComponent())
        
        self._split_pane.setBottomComponent(tabs_pane)
        self._split_pane.setDividerLocation(300)
        
        self._panel.add(self._split_pane, BorderLayout.CENTER)
        
        self._currently_displayed_item = None

    def minimize_native_history(self, event):
        def task():
            start_time = time.time()
            self.set_status("Scanning history...")
            
            history = self._callbacks.getProxyHistory()
            total = len(history)
            seen = set()
            count = 0
            
            for i, item in enumerate(history):
                if i % 100 == 0:
                    self.set_status("Processing: %d/%d" % (i, total))
                    
                req = item.getRequest()
                if not req: continue
                
                try:
                    # Robust Method/Path Extraction
                    # Find indices of first and second spaces
                    first_space = -1
                    second_space = -1
                    for j in range(len(req)):
                        if req[j] == 32: # ' '
                            if first_space == -1: first_space = j
                            else:
                                second_space = j
                                break
                    
                    if first_space == -1 or second_space == -1: continue
                    path_part = self._helpers.bytesToString(req[first_space+1:second_space])
                    
                    service = item.getHttpService()
                    # Key: (Response Length, Path, Host, Port, Protocol)
                    # We include more details to ensure 100% accuracy
                    
                    res = item.getResponse()
                    length = 0
                    if res:
                        # Find \r\n\r\n divider efficiently
                        offset = len(res)
                        for k in range(len(res) - 3):
                            if res[k] == 13 and res[k+1] == 10 and res[k+2] == 13 and res[k+3] == 10:
                                offset = k + 4
                                break
                        length = len(res) - offset
                    
                    key = (length, path_part, service.getHost(), service.getPort(), service.getProtocol())
                    
                    if key in seen:
                        if item.getComment() != "duplicate":
                            item.setComment("duplicate")
                        count += 1
                    else:
                        seen.add(key)
                        if item.getComment() == "duplicate":
                            item.setComment(None)
                except Exception as e:
                    print("Error processing item %d: %s" % (i, str(e)))
                    continue
            
            duration = time.time() - start_time
            result_msg = "Done. Tagged %d duplicates in %.2fs." % (count, duration)
            self.set_status(result_msg)
            print(result_msg)

        threading.Thread(target=task).start()

    def set_status(self, text):
        def update():
            self._status_label.setText(text)
        SwingUtilities.invokeLater(update)

    def clear_custom_tab(self, event):
        def clear_ui():
            with self._lock:
                self._seen_keys.clear()
                self._log = []
                self._currently_displayed_item = None
            
            # Perform UI updates on the Event Dispatch Thread
            self._table_model.setRowCount(0)
            self._request_viewer.setMessage(None, False)
            self._response_viewer.setMessage(None, False)
            print("Custom tab cleared.")

        SwingUtilities.invokeLater(clear_ui)

    # ITab Implementation
    def getTabCaption(self):
        return "URL Minimizer"
        
    def getUiComponent(self):
        return self._panel

    # IContextMenuFactory Implementation
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Send to URL Minimizer", actionPerformed=lambda x: self.process_selection(invocation))
        menu_list.add(menu_item)
        return menu_list

    def process_selection(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses:
            for messageInfo in responses:
                self.filter_and_add(messageInfo)
            
    def filter_and_add(self, messageInfo):
        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()
        if not request_bytes: return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())
        host = messageInfo.getHttpService().getHost()
        method = request_info.getMethod()
        
        status = ""
        content_length = 0
        mime_type = ""
        extension = ""
        
        if response_bytes:
            response_info = self._helpers.analyzeResponse(response_bytes)
            status = str(response_info.getStatusCode())
            content_length = len(response_bytes) - response_info.getBodyOffset()
            mime_type = response_info.getStatedMimeType()
        
        unique_key = (content_length, url, host)
        
        with self._lock:
            if unique_key not in self._seen_keys:
                self._seen_keys.add(unique_key)
                should_add = True
                row_idx = len(self._log)
                self._log.append(messageInfo)
            else:
                should_add = False

        if should_add:
            has_params = "Y" if request_info.getParameters() else "N"
            path = request_info.getUrl().getPath()
            if "." in path: extension = path.split(".")[-1]
            
            arrival_time = time.strftime("%H:%M:%S", time.localtime())
            
            # Separate the UI update from the logic lock
            def add_row():
                self._table_model.addRow([
                    row_idx + 1, host, method, url, has_params, status, content_length, mime_type, extension, arrival_time
                ])
            SwingUtilities.invokeLater(add_row)

    def row_selected(self, event):
        if not event.getValueIsAdjusting():
            selected_row = self._table.getSelectedRow()
            if selected_row != -1:
                model_row = self._table.convertRowIndexToModel(selected_row)
                message_info = self._log[model_row]
                self._currently_displayed_item = message_info
                self._request_viewer.setMessage(message_info.getRequest(), True)
                self._response_viewer.setMessage(message_info.getResponse() if message_info.getResponse() else None, False)

    # IMessageEditorController
    def getHttpService(self): return self._currently_displayed_item.getHttpService() if self._currently_displayed_item else None
    def getRequest(self): return self._currently_displayed_item.getRequest() if self._currently_displayed_item else None
    def getResponse(self): return self._currently_displayed_item.getResponse() if self._currently_displayed_item else None

class TableMouseListener(MouseAdapter):
    def __init__(self, extender): self._extender = extender
    def mouseReleased(self, event):
        if event.isPopupTrigger(): self.show_popup(event)
    def mousePressed(self, event):
        if event.isPopupTrigger(): self.show_popup(event)

    def show_popup(self, event):
        source = event.getSource()
        row = source.rowAtPoint(event.getPoint())
        if not source.isRowSelected(row): source.setRowSelectionInterval(row, row)
            
        menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater", actionPerformed=lambda x: self.action_handler("repeater")))
        menu.add(JMenuItem("Send to Intruder", actionPerformed=lambda x: self.action_handler("intruder")))
        menu.add(JMenuItem("Send to Sequencer", actionPerformed=lambda x: self.action_handler("sequencer")))
        menu.addSeparator()
        menu.add(JMenuItem("Actively Scan", actionPerformed=lambda x: self.action_handler("active_scan")))
        menu.add(JMenuItem("Passively Scan", actionPerformed=lambda x: self.action_handler("passive_scan")))
        menu.addSeparator()
        menu.add(JMenuItem("Send to Comparer", actionPerformed=lambda x: self.action_handler("comparer")))
        menu.addSeparator()
        menu.add(JMenuItem("Copy URL", actionPerformed=lambda x: self.action_handler("copy_url")))
        menu.add(JMenuItem("Copy as Curl", actionPerformed=lambda x: self.action_handler("copy_curl")))
        
        menu.show(source, event.getX(), event.getY())

    def action_handler(self, action_type):
        selected_rows = self._extender._table.getSelectedRows()
        for row in selected_rows:
            model_row = self._extender._table.convertRowIndexToModel(row)
            message_info = self._extender._log[model_row]
            service = message_info.getHttpService()
            request = message_info.getRequest()
            is_https = service.getProtocol() == "https"
            
            if action_type == "repeater": self._extender._callbacks.sendToRepeater(service.getHost(), service.getPort(), is_https, request, None)
            elif action_type == "intruder": self._extender._callbacks.sendToIntruder(service.getHost(), service.getPort(), is_https, request)
            elif action_type == "sequencer": self._extender._callbacks.sendToSequencer(service.getHost(), service.getPort(), is_https, request)
            elif action_type == "active_scan": self._extender._callbacks.doActiveScan(service.getHost(), service.getPort(), is_https, request)
            elif action_type == "passive_scan": self._extender._callbacks.doPassiveScan(service.getHost(), service.getPort(), is_https, request, message_info.getResponse())
            elif action_type == "comparer":
                self._extender._callbacks.sendToComparer(request)
                if message_info.getResponse(): self._extender._callbacks.sendToComparer(message_info.getResponse())
            elif action_type == "copy_url": self.copy_to_clipboard(str(self._extender._helpers.analyzeRequest(message_info).getUrl()))
            elif action_type == "copy_curl": self.copy_to_clipboard(self.generate_curl(message_info))

    def copy_to_clipboard(self, text):
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        selection = StringSelection(text)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, None)

    def generate_curl(self, message_info):
        req_info = self._extender._helpers.analyzeRequest(message_info)
        url = str(req_info.getUrl())
        method = req_info.getMethod()
        headers = req_info.getHeaders()
        
        curl = "curl -X %s '%s'" % (method, url)
        for i in range(1, len(headers)): # Skip first header (method/path)
            curl += " -H '%s'" % headers[i]
        
        body_bytes = message_info.getRequest()[req_info.getBodyOffset():]
        if body_bytes:
            body_str = self._extender._helpers.bytesToString(body_bytes)
            # Simple escaping for curl
            curl += " --data-raw '%s'" % body_str.replace("'", "'\\''")
            
        return curl
