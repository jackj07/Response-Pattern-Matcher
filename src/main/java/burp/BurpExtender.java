package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener {
    //Static Burp objects
    protected static IBurpExtenderCallbacks callbacks;
    protected static IExtensionHelpers helpers;
    protected static PrintWriter stdout;
    protected static PrintWriter sterror;

    //Scope
    private Boolean inScopeOnly = false;

    //Main Splitpane
    JSplitPane splitPane_main;

    //Threading and sync'd lists
    private List<Payload> payloads = Collections.synchronizedList(new ArrayList<Payload>());
    private List<ResultEntry> results = Collections.synchronizedList(new ArrayList<ResultEntry>());
    private int threadCount = Runtime.getRuntime().availableProcessors();
    private ExecutorService service = Executors.newFixedThreadPool(threadCount);

    //Tables and table models
    private ResultsTableModel resultsTableModel = new ResultsTableModel(results);
    private PayloadsTableModel payloadsTableModel = new PayloadsTableModel(payloads);
    private ResultTable table_Results;
    private PayloadTable table_payloads;

    //Controller class (passed to tables)
    private ContentController contentController = new ContentController();//request, response, and selected rows in tables

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        //Terminal Output
        stdout = new PrintWriter(callbacks.getStdout(), true);
        sterror = new PrintWriter(callbacks.getStderr(), true);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Scraper");

        // create our UI
        SwingUtilities.invokeLater(() -> {
            // main split pane declaration
            splitPane_main = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // Results and Input Pane (top half)
            JSplitPane splitPane_ResultsAndInput = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

            // table of log entries (bottom half of top half)
            table_Results = new ResultTable(resultsTableModel, results, contentController);
            table_Results.getColumnModel().getColumn(0).setPreferredWidth(5);
            table_Results.getColumnModel().getColumn(1).setPreferredWidth(20);
            table_Results.getColumnModel().getColumn(2).setPreferredWidth(400);
            table_Results.getColumnModel().getColumn(3).setPreferredWidth(30);
            table_Results.getColumnModel().getColumn(4).setPreferredWidth(600);
            table_Results.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            JScrollPane scrollPane_Results = new JScrollPane(table_Results);
            scrollPane_Results.setPreferredSize(new Dimension(0,330));
            splitPane_ResultsAndInput.setRightComponent(scrollPane_Results);

            // user input section (top half of top half)
            JPanel panel_input_outer = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JPanel panel_input = new JPanel();
            panel_input.setPreferredSize(new Dimension(400, 350));
            panel_input.setLayout(new BoxLayout(panel_input, BoxLayout.PAGE_AXIS));

            // User Input Label
            JPanel panel_label_title = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_title = new JLabel("Wordlist Input");
            label_title.setHorizontalAlignment(SwingConstants.CENTER);
            panel_label_title.add(label_title);
            panel_input.add(panel_label_title);

            // Payloads Input
            JPanel panel_table_payloads = new JPanel(new FlowLayout(FlowLayout.CENTER));
            table_payloads = new PayloadTable(payloadsTableModel, contentController);
            JScrollPane scrollPane_payloads = new JScrollPane(table_payloads);
            scrollPane_payloads.setPreferredSize(new Dimension(350, 180));
            panel_table_payloads.add(scrollPane_payloads);
            panel_input.add(panel_table_payloads);

            //Button Load
            JPanel panel_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_upload = new JButton("Load ...");
            button_upload.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    if (e.getSource() == button_upload) {
                        final JFileChooser fc = new JFileChooser();
                        int returnVal = fc.showOpenDialog(panel_buttons);

                        if (returnVal == JFileChooser.APPROVE_OPTION) {
                            File file = fc.getSelectedFile();
                            BufferedReader reader = null;
                            try {
                                String filePath = file.getPath();

                                reader = new BufferedReader(new FileReader(filePath));
                                for(String line; (line = reader.readLine()) != null;) {
                                    int row = payloads.size();
                                    payloads.add(new Payload(line, false));
                                    payloadsTableModel.fireTableRowsInserted(row, row);
                                }
                            } catch (IOException ex) {
                                sterror.println("An IOException occurred attempting to Load file");
                                sterror.println(ex.getMessage());
                            }finally {
                                if(reader != null){
                                    try{
                                        reader.close();
                                    }catch(IOException ex2){
                                        sterror.println("Cannot close file reader");
                                        sterror.println(ex2.getMessage());
                                    }
                                }
                            }
                        } else {
                            stdout.println("File load cancelled");
                        }
                    }
                }
            });
            panel_buttons.add(button_upload);

            //Button Remove
            JButton button_remove = new JButton("Remove");
            button_remove.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent e)
                {
                    if(contentController.getSelectedPayloadRow() >=0){
                        payloads.remove(contentController.getSelectedPayloadRow());
                        payloadsTableModel.fireTableRowsDeleted(contentController.getSelectedPayloadRow(), contentController.getSelectedPayloadRow());
                        contentController.setSelectedPayloadRow(-1);
                    }
                }
            });
            panel_buttons.add(button_remove);

            //Button Clear
            JButton button_clear = new JButton("Clear");
            button_clear.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e){
                    int row = payloads.size();
                    payloads.clear();
                    payloadsTableModel.fireTableRowsDeleted(0,row);
                }
            });
            panel_buttons.add(button_clear);

            //Checkbox is in scope
            JCheckBox checkBox_isInScope = new JCheckBox("In Scope Only");
            checkBox_isInScope.addItemListener(new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent e) {
                    if(e.getStateChange() == ItemEvent.SELECTED) {//checkbox has been selected
                        inScopeOnly = true;
                    } else {
                        inScopeOnly = false;
                    };
                }
            });
            panel_buttons.add(checkBox_isInScope);
            panel_input.add(panel_buttons);

            //Single Input Text field
            JPanel panel_single_input = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JTextField textField_input = new JTextField(25);
            panel_single_input.add(textField_input);

            //Single Input Button
            JButton button_add = new JButton("Add");
            // add the listener to the add jbutton
            button_add.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent e) {
                    String input = textField_input.getText();
                    if(input != null && !input.isEmpty()){
                        int row = payloads.size();
                        payloads.add(new Payload(input, false));
                        payloadsTableModel.fireTableRowsInserted(row, row);
                    }
                }
            });
            panel_single_input.add(button_add);
            panel_input.add(panel_single_input);

            //Clear results table Button
            JPanel panel_button_clear_results = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_clear_results = new JButton("Clear Results");
            button_clear_results.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e){
                    synchronized (results) {
                        results.clear();
                        contentController.getRequestViewer().setMessage(new byte[0], true);
                        contentController.getResponseViewer().setMessage(new byte[0], false);
                        resultsTableModel.fireTableDataChanged();
                    }
                }
            });
            panel_button_clear_results.add(button_clear_results);
            panel_input.add(panel_button_clear_results);

            panel_input_outer.add(panel_input);

            //
            splitPane_ResultsAndInput.setLeftComponent(panel_input_outer);

            // tabs with request/response viewers (bottom half)
            JTabbedPane tabs = new JTabbedPane();
            contentController.setRequestViewer(callbacks.createMessageEditor(BurpExtender.this, false));
            contentController.setResponseViewer(callbacks.createMessageEditor(BurpExtender.this, false));
            tabs.addTab("Request", contentController.getRequestViewer().getComponent());
            tabs.addTab("Response", contentController.getResponseViewer().getComponent());

            // main split pane, setting the components
            splitPane_main.setRightComponent(tabs);
            splitPane_main.setLeftComponent(splitPane_ResultsAndInput);

            // customize our UI components
            callbacks.customizeUiComponent(splitPane_main);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(BurpExtender.this);
        });

        //Default payloads
        payloads.add(new Payload("admin", false));
        payloads.add(new Payload("password", false));
        payloads.add(new Payload("passcode", false));
        payloads.add(new Payload("port.{0,7}\\d+", true));
        payloads.add(new Payload("sql", false));
        payloads.add(new Payload("<!--", false));
        payloads.add(new Payload("/*", false));
        payloads.add(new Payload("todo", false));
        payloads.add(new Payload("secret", false));
        payloads.add(new Payload("//# sourceURL", false));
        payloads.add(new Payload("//# sourceMappingURL", false));
        payloads.add(new Payload("api", false));
        payloads.add(new Payload("private", false));
        payloads.add(new Payload("debug", false));

        //Loading complete
        stdout.println("Scraper Extension Loaded");
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption(){
        return "Scraper";
    }

    @Override
    public Component getUiComponent(){
        return splitPane_main;
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        service.execute(new MessageProcessor(toolFlag, messageInfo, inScopeOnly, messageIsRequest, payloads, results, resultsTableModel, table_Results));
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //
    @Override
    public byte[] getRequest() {
        return contentController.getCurrentlyDisplayedItem().getRequest();
    }

    @Override
    public byte[] getResponse() {
        return contentController.getCurrentlyDisplayedItem().getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return contentController.getCurrentlyDisplayedItem().getHttpService();
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Scraper unloaded");

        //Close Thread Pool
        service.shutdownNow();
    }
}