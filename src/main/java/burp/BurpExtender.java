package burp;

import com.coreyd97.BurpExtenderUtilities.*;
import com.google.gson.reflect.TypeToken;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import javax.swing.*;
import javax.swing.border.EtchedBorder;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener,
    IContextMenuFactory{
    //Static Burp objects
    protected static IBurpExtenderCallbacks callbacks;
    protected static IExtensionHelpers helpers;
    protected static PrintWriter stdout;
    protected static PrintWriter sterror;

    //Scope
    private Boolean inScopeOnly;
    private Boolean matchOnResponses;
    private Boolean matchOnRequests;

    //Checkboxes need to be accessible for setDefaults()
    JCheckBox checkBox_isInScope;
    JCheckBox checkBox_matchOnResponses;
    JCheckBox checkBox_matchOnRequests;

    //Main outer component
    JTabbedPane tabs_outer;

    //Threading and sync'd lists
    private List<Payload> payloads;
    private List<ResultEntry> results_responses = Collections.synchronizedList(new ArrayList<ResultEntry>());
    private List<ResultEntry> results_requests = Collections.synchronizedList(new ArrayList<ResultEntry>());
    private int threadCount = Runtime.getRuntime().availableProcessors();
    private ExecutorService service = Executors.newFixedThreadPool(threadCount);

    //Tables and table models
    private ResultsTableModel resultsTableModel_responses = new ResultsTableModel(results_responses);
    private ResultsTableModel resultsTableModel_requests = new ResultsTableModel(results_requests);
    private PayloadsTableModel payloadsTableModel;
    private ResultTable table_results_responses;
    private ResultTable table_results_requests;
    private PayloadTable table_payloads;

    //Controller class (passed to tables)
    private ContentController contentController = new ContentController();//request, response, and selected rows in tables

    //BurpExtenderUtilities (Credit: CoreyD97) used to save configs
    private Preferences prefs;

    //If run for the first time
    private Boolean firstRun;

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

        //Define the preferences objects
        prefs = new Preferences("Response Pattern Matcher", new DefaultGsonProvider(), callbacks);
        prefs.registerSetting("Payloads", new TypeToken<List<Payload>>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("In Scope Only", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("First Run", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("Match On Responses", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("Match On Requests", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);

        //Get the saved payloads from the Preferences object
        payloads = (prefs.getSetting("Payloads") == null)
                ? Collections.synchronizedList(new ArrayList<Payload>())
                : Collections.synchronizedList(prefs.getSetting("Payloads"));
        payloadsTableModel = new PayloadsTableModel(payloads, prefs);

        // set our extension name
        callbacks.setExtensionName("Response Pattern Matcher");

        // create UI
        SwingUtilities.invokeLater(() -> {
            // Main Panel for user input items (Config Tab)
            JPanel panel_input = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JScrollPane scrollPane_input = new JScrollPane(panel_input);
            panel_input.setLayout(new BoxLayout(panel_input, BoxLayout.PAGE_AXIS));

            // Wordlist Input Label (Config Tab)
            JPanel panel_label_wordlist = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_wordlist = new JLabel("Wordlist Input");
            label_wordlist.setHorizontalAlignment(SwingConstants.CENTER);
            panel_label_wordlist.add(label_wordlist);
            panel_input.add(panel_label_wordlist);

            // Payloads Input (Config Tab)
            JPanel panel_table_payloads = new JPanel(new FlowLayout(FlowLayout.CENTER));
            table_payloads = new PayloadTable(payloadsTableModel, contentController);
            table_payloads.getColumnModel().getColumn(0).setPreferredWidth(420);
            table_payloads.getColumnModel().getColumn(1).setPreferredWidth(80);
            table_payloads.getColumnModel().getColumn(2).setPreferredWidth(80);
            table_payloads.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            JScrollPane scrollPane_payloads = new JScrollPane(table_payloads);
            scrollPane_payloads.setPreferredSize(new Dimension(600, 270));
            panel_table_payloads.add(scrollPane_payloads);
            panel_input.add(panel_table_payloads);

            //Button Load (Config Tab)
            JPanel panel_wordlist_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_upload = new JButton("Load ...");
            button_upload.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    if (e.getSource() == button_upload) {
                        final JFileChooser fc = new JFileChooser();
                        int returnVal = fc.showOpenDialog(panel_wordlist_buttons);

                        if (returnVal == JFileChooser.APPROVE_OPTION) {
                            File file = fc.getSelectedFile();
                            BufferedReader reader = null;
                            try {
                                String filePath = file.getPath();

                                reader = new BufferedReader(new FileReader(filePath));
                                for(String line; (line = reader.readLine()) != null;) {
                                    if(line == null || line.equals(""))continue;//prevent empty items being added
                                    int row = payloads.size();
                                    payloads.add(new Payload(line, false, true));
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
                                prefs.setSetting("Payloads", payloads);
                            }
                        } else {
                            stdout.println("File load cancelled");
                        }
                    }
                }
            });
            panel_wordlist_buttons.add(button_upload);

            //Button Remove (Config Tab)
            JButton button_remove = new JButton("Remove");
            button_remove.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent e)
                {
                    if(contentController.getSelectedPayloadRow() >=0){
                        payloads.remove(contentController.getSelectedPayloadRow());
                        payloadsTableModel.fireTableRowsDeleted(contentController.getSelectedPayloadRow(), contentController.getSelectedPayloadRow());
                        contentController.setSelectedPayloadRow(-1);
                        prefs.setSetting("Payloads", payloads);
                    }
                }
            });
            panel_wordlist_buttons.add(button_remove);

            //Button Clear (Config Tab)
            JButton button_clear = new JButton("Clear");
            button_clear.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e){
                    int row = payloads.size();
                    payloads.clear();
                    payloadsTableModel.fireTableRowsDeleted(0,row);
                    prefs.setSetting("Payloads", payloads);
                }
            });
            panel_wordlist_buttons.add(button_clear);

            //Button Restore Defaults (Config Tab)
            JButton button_restoreDefaults = new JButton("Restore Defaults");
            button_restoreDefaults.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    restoreDefaults();
                }
            });
            panel_wordlist_buttons.add(button_restoreDefaults);

            //Checkbox is in scope (Config Tab)
            inScopeOnly = prefs.getSetting("In Scope Only");
            if(inScopeOnly == null)inScopeOnly = true;
            checkBox_isInScope = new JCheckBox("In Scope Only", inScopeOnly);
            checkBox_isInScope.addItemListener(new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent e) {
                    if(e.getStateChange() == ItemEvent.SELECTED) {//checkbox has been selected
                        inScopeOnly = true;
                        prefs.setSetting("In Scope Only", inScopeOnly);
                    } else {
                        inScopeOnly = false;
                        prefs.setSetting("In Scope Only", inScopeOnly);
                    };
                }
            });
            panel_wordlist_buttons.add(checkBox_isInScope);
            panel_input.add(panel_wordlist_buttons);

            //Single Input Text field (Config Tab)
            JPanel panel_single_input = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JTextField textField_input = new JTextField(25);
            panel_single_input.add(textField_input);

            //Single Input Button (Config Tab)
            JButton button_add = new JButton("Add");
            button_add.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent e) {
                    String input = textField_input.getText();
                    if(input != null && !input.isEmpty()){
                        int row = payloads.size();
                        payloads.add(new Payload(input, false, true));
                        payloadsTableModel.fireTableRowsInserted(row, row);
                        textField_input.setText("");
                        prefs.setSetting("Payloads", payloads);
                    }
                }
            });
            panel_single_input.add(button_add);
            panel_input.add(panel_single_input);

            //First Separator (Config Tab)
            panel_input.add(new JSeparator());

            // Response Config Label (Config Tab)
            JPanel panel_label_responses = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_responses = new JLabel("Response Match Configuration");
            label_responses.setHorizontalAlignment(SwingConstants.CENTER);
            panel_label_responses.add(label_responses);
            panel_input.add(panel_label_responses);

            //Clear response results table Button (Config Tab)
            JPanel panel_responseconfig_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_clear_responses = new JButton("Clear Matches On Responses");
            button_clear_responses.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e){
                    synchronized (results_responses) {
                        results_responses.clear();
                        contentController.getRequestViewer().setMessage(new byte[0], true);
                        contentController.getResponseViewer().setMessage(new byte[0], false);
                        resultsTableModel_responses.fireTableDataChanged();
                    }
                }
            });
            panel_responseconfig_buttons.add(button_clear_responses);

            //Checkbox match on responses (Config Tab)
            matchOnResponses = prefs.getSetting("Match On Responses");
            if(matchOnResponses == null)matchOnResponses = true;
            checkBox_matchOnResponses = new JCheckBox("Match On Responses", matchOnResponses);
            checkBox_matchOnResponses.addItemListener(new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent e) {
                    if(e.getStateChange() == ItemEvent.SELECTED) {//checkbox has been selected
                        matchOnResponses = true;
                        prefs.setSetting("Match On Responses", matchOnResponses);
                    } else {
                        matchOnResponses = false;
                        prefs.setSetting("Match On Responses", matchOnResponses);
                    };
                }
            });
            panel_responseconfig_buttons.add(checkBox_matchOnResponses);
            panel_input.add(panel_responseconfig_buttons);

            //Second Separator (Config Tab)
            panel_input.add(new JSeparator());

            // Request Config Label (Config Tab)
            JPanel panel_label_requests = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_requests = new JLabel("Request Match Configuration");
            label_requests.setHorizontalAlignment(SwingConstants.CENTER);
            panel_label_requests.add(label_requests);
            panel_input.add(panel_label_requests);

            //Clear requests table Button (Config Tab)
            JPanel panel_requestconfig_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_clear_requests = new JButton("Clear Matches On Requests");
            button_clear_requests.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e){
                    synchronized (results_requests) {
                        results_requests.clear();
                        contentController.getRequestViewer().setMessage(new byte[0], true);
                        contentController.getResponseViewer().setMessage(new byte[0], false);
                        resultsTableModel_requests.fireTableDataChanged();
                    }
                }
            });
            panel_requestconfig_buttons.add(button_clear_requests);

            //Checkbox match on responses (Config Tab)
            matchOnRequests = prefs.getSetting("Match On Requests");
            if(matchOnRequests == null)matchOnRequests = false;
            checkBox_matchOnRequests = new JCheckBox("Match On Requests", matchOnRequests);
            checkBox_matchOnRequests.addItemListener(new ItemListener() {
                @Override
                public void itemStateChanged(ItemEvent e) {
                    if(e.getStateChange() == ItemEvent.SELECTED) {//checkbox has been selected
                        matchOnRequests = true;
                        prefs.setSetting("Match On Requests", matchOnRequests);
                    } else {
                        matchOnRequests = false;
                        prefs.setSetting("Match On Requests", matchOnRequests);
                    };
                }
            });
            panel_requestconfig_buttons.add(checkBox_matchOnRequests);
            panel_input.add(panel_requestconfig_buttons);

            // main split pane for response items (Results Tab)
            JSplitPane splitPane_results = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            JTabbedPane tabbedPane_results = new JTabbedPane();

            // table of log entries (Results Tab - Responses)
            table_results_responses = new ResultTable(resultsTableModel_responses, results_responses, contentController);
            table_results_responses.getColumnModel().getColumn(0).setPreferredWidth(5);
            table_results_responses.getColumnModel().getColumn(1).setPreferredWidth(20);
            table_results_responses.getColumnModel().getColumn(2).setPreferredWidth(400);
            table_results_responses.getColumnModel().getColumn(3).setPreferredWidth(30);
            table_results_responses.getColumnModel().getColumn(4).setPreferredWidth(600);
            table_results_responses.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            JScrollPane scrollPane_Responses = new JScrollPane(table_results_responses);
            scrollPane_Responses.setPreferredSize(new Dimension(0,330));
            tabbedPane_results.addTab("Matches On Responses", scrollPane_Responses);

            // table of log entries (Results Tab - Requests)
            table_results_requests = new ResultTable(resultsTableModel_requests, results_requests, contentController);
            table_results_requests.getColumnModel().getColumn(0).setPreferredWidth(5);
            table_results_requests.getColumnModel().getColumn(1).setPreferredWidth(20);
            table_results_requests.getColumnModel().getColumn(2).setPreferredWidth(400);
            table_results_requests.getColumnModel().getColumn(3).setPreferredWidth(30);
            table_results_requests.getColumnModel().getColumn(4).setPreferredWidth(600);
            table_results_requests.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            JScrollPane scrollPane_Requests = new JScrollPane(table_results_requests);
            scrollPane_Requests.setPreferredSize(new Dimension(0,330));
            tabbedPane_results.addTab("Matches On Requests", scrollPane_Requests);
            splitPane_results.setLeftComponent(tabbedPane_results);

            //Tabbed pane with request/response viewers (Results Tab)
            JTabbedPane tabs_requestResponses = new JTabbedPane();
            contentController.setRequestViewer(callbacks.createMessageEditor(BurpExtender.this, false));
            contentController.setResponseViewer(callbacks.createMessageEditor(BurpExtender.this, false));
            tabs_requestResponses.addTab("Request", contentController.getRequestViewer().getComponent());
            tabs_requestResponses.addTab("Response", contentController.getResponseViewer().getComponent());
            splitPane_results.setRightComponent(tabs_requestResponses);

            // Main Panel for more info (About Tab)
            JPanel panel_about = new JPanel();
            JScrollPane scrollPane_about = new JScrollPane(panel_about);

            JPanel panel_about_contents = new JPanel();
            panel_about_contents.setPreferredSize(new Dimension(300,250));
            panel_about_contents.setLayout(new BoxLayout(panel_about_contents, BoxLayout.PAGE_AXIS));
            panel_about_contents.setBorder(BorderFactory.createEtchedBorder(EtchedBorder.LOWERED));

            JPanel panel_about_author = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_author = new JLabel("Author");
            label_author.setHorizontalAlignment(SwingConstants.CENTER);
            label_author.setVerticalAlignment(SwingConstants.TOP);
            label_author.setFont(new Font(label_author.getName(), Font.PLAIN, 20));
            panel_about_author.add(label_author);
            panel_about_contents.add(panel_about_author);

            JPanel panel_about_name = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_name = new JLabel("Jack Jarvis");
            panel_about_name.add(label_name);
            panel_about_contents.add(panel_about_name);

            JPanel panel_about_tag = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_tag = new JLabel("Web Hacking Enthusiast");
            panel_about_tag.add(label_tag);
            panel_about_contents.add(panel_about_tag);

            JPanel panel_about_role = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_role = new JLabel("Security Consultant");
            panel_about_role.add(label_role);
            panel_about_contents.add(panel_about_role);

            JPanel panel_about_follow = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_follow = new JLabel("Find Me On");
            label_follow.setPreferredSize(new Dimension(500,50));
            label_follow.setHorizontalAlignment(SwingConstants.CENTER);
            label_follow.setVerticalAlignment(SwingConstants.BOTTOM);
            label_follow.setFont(new Font(label_author.getName(), Font.PLAIN, 20));
            panel_about_follow.add(label_follow);
            panel_about_contents.add(panel_about_follow);

            JPanel panel_github = new JPanel(new FlowLayout(FlowLayout.CENTER));
            String githubURL="https://github.com/JackJ07";
            JHyperlink githubLogo = new JHyperlink(new ImageIcon(getClass().getClassLoader().getResource("GitHub-Mark-32px.png")),githubURL, githubURL);
            githubLogo.setPreferredSize(new Dimension(80, 50));
            panel_github.add(githubLogo);
            String twitterURL="https://twitter.com/JackJarvis07";
            JHyperlink twitterLogo = new JHyperlink(new ImageIcon(getClass().getClassLoader().getResource("Twitter_Logo_Blue_42px.png")), twitterURL, twitterURL);
            twitterLogo.setPreferredSize(new Dimension(80, 50));
            panel_github.add(twitterLogo);
            panel_about_contents.add(panel_github);

            panel_about.add(panel_about_contents);

            //Setting up the tabs
            tabs_outer = new JTabbedPane();
            tabs_outer.addTab("Config", scrollPane_input);
            tabs_outer.addTab("Matches", splitPane_results);
            tabs_outer.addTab("About", scrollPane_about);

            // customize our UI components
            callbacks.customizeUiComponent(tabs_outer);

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(BurpExtender.this);

            //Setup configs for first time usage
            firstRun = prefs.getSetting("First Run");
            if(firstRun == null){
                restoreDefaults();
                prefs.setSetting("First Run", false);
            }

            stdout.println("Extension Loaded Successfully");
        });
    }

    private void restoreDefaults(){
        //Default payloads
        payloads.clear();
        payloads.add(new Payload("admin", false, true));
        payloads.add(new Payload("password", false, true));
        payloads.add(new Payload("passcode", false, true));
        payloads.add(new Payload("port.{0,7}\\d+", true, true));
        payloads.add(new Payload("sql", false, true));
        payloads.add(new Payload("<!--", false, true));
        payloads.add(new Payload("/*", false, true));
        payloads.add(new Payload("todo", false, true));
        payloads.add(new Payload("secret", false, true));
        payloads.add(new Payload("//# sourceURL", false, true));
        payloads.add(new Payload("//# sourceMappingURL", false, true));
        payloads.add(new Payload("api", false, true));
        payloads.add(new Payload("private", false, true));
        payloads.add(new Payload("debug", false, true));
        payloadsTableModel.fireTableDataChanged();
        prefs.setSetting("Payloads", payloads);

        inScopeOnly = true;
        prefs.setSetting("In Scope Only", inScopeOnly);
        checkBox_isInScope.setSelected(true);

        matchOnResponses = true;
        prefs.setSetting("Match On Responses", matchOnResponses);
        checkBox_matchOnResponses.setSelected(true);

        matchOnRequests = false;
        prefs.setSetting("Match On Requests", matchOnRequests);
        checkBox_matchOnRequests.setSelected(false);
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption(){
        return "Response Pattern Matcher";
    }

    @Override
    public Component getUiComponent(){
        return tabs_outer;
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        service.execute(new MessageProcessor(toolFlag, messageInfo, inScopeOnly, messageIsRequest, matchOnRequests,
                matchOnResponses, payloads, results_responses, results_requests, resultsTableModel_responses, resultsTableModel_requests));
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
        //Close Thread Pool
        service.shutdownNow();

        stdout.println("Extension Unloaded Successfully");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> jMenuItems = new LinkedList<JMenuItem>();
        jMenuItems.add(new JMenuItem("testing"));
        return jMenuItems;
    }
}