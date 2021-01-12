package rpm.ui;

import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import rpm.Payload;
import rpm.ResponsePatternMatcher;
import rpm.ResultEntry;

import rpm.controller.ContentController;

import rpm.model.PayloadsTableModel;
import rpm.model.ResultsTableModel;

import javax.swing.*;
import javax.swing.border.EtchedBorder;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class GUI {
    private Preferences prefs; //BurpExtenderUtilities (Credit: CoreyD97) used to save configs
    private Boolean inScopeOnly;
    private Boolean matchOnResponses;
    private Boolean matchOnRequests;
    private ResponsePatternMatcher responsePatternMatcher;
    private List<Payload> payloads;
    private List<ResultEntry> results_responses;
    private List<ResultEntry> results_requests;

    //Controller
    private ContentController contentController;

    //Model
    private PayloadsTableModel payloadsTableModel;
    private ResultsTableModel resultsTableModel_responses;
    private ResultsTableModel resultsTableModel_requests;

    //UI
    private JCheckBox checkBox_isInScope;
    private JCheckBox checkBox_matchOnResponses;
    private JCheckBox checkBox_matchOnRequests;
    private JTabbedPane tabs_outer;
    private PayloadTable table_payloads;
    private ResultTable table_results_responses;
    private ResultTable table_results_requests;

    public GUI(ContentController contentController, ResponsePatternMatcher responsePatternMatcher){
        this.contentController = contentController;
        this.responsePatternMatcher = responsePatternMatcher;
        this.results_responses = Collections.synchronizedList(new ArrayList<>());
        this.results_requests = Collections.synchronizedList(new ArrayList<>());
        this.resultsTableModel_responses = new ResultsTableModel(results_responses);
        this.resultsTableModel_requests = new ResultsTableModel(results_requests);
    }

    public void initialise(){
        //Define the preferences objects
        prefs = new Preferences("Response Pattern Matcher", new DefaultGsonProvider(), ResponsePatternMatcher.callbacks);
        prefs.registerSetting("Payloads", new TypeToken<List<Payload>>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("In Scope Only", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("First Run", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("Match On Responses", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);
        prefs.registerSetting("Match On Requests", new TypeToken<Boolean>(){}.getType(), Preferences.Visibility.GLOBAL);

        //Get the saved payloads from the Preferences object
        payloads = (prefs.getSetting("Payloads") == null)
                ? Collections.synchronizedList(new ArrayList<>())
                : Collections.synchronizedList(prefs.getSetting("Payloads"));
        payloadsTableModel = new PayloadsTableModel(payloads, prefs);

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
            table_payloads.setDefaultColumnSizes();
            JScrollPane scrollPane_payloads = new JScrollPane(table_payloads);
            scrollPane_payloads.setPreferredSize(new Dimension(600, 270));
            panel_table_payloads.add(scrollPane_payloads);
            panel_input.add(panel_table_payloads);

            //Button Load (Config Tab)
            JPanel panel_wordlist_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_upload = new JButton("Load ...");
            button_upload.addActionListener(e -> {
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
                            ResponsePatternMatcher.stderror.println("An IOException occurred attempting to Load file");
                            ResponsePatternMatcher.stderror.println(ex.getMessage());
                        }finally {
                            if(reader != null){
                                try{
                                    reader.close();
                                }catch(IOException ex2){
                                    ResponsePatternMatcher.stderror.println("Cannot close file reader");
                                    ResponsePatternMatcher.stderror.println(ex2.getMessage());
                                }
                            }
                            prefs.setSetting("Payloads", payloads);
                        }
                    } else {
                        ResponsePatternMatcher.stdout.println("File load cancelled");
                    }
                }
            });
            panel_wordlist_buttons.add(button_upload);

            //Button Remove (Config Tab)
            JButton button_remove = new JButton("Remove");
            button_remove.addActionListener(e -> {
                if(contentController.getSelectedPayloadRow() >=0){
                    payloads.remove(contentController.getSelectedPayloadRow());
                    payloadsTableModel.fireTableRowsDeleted(contentController.getSelectedPayloadRow(), contentController.getSelectedPayloadRow());
                    contentController.setSelectedPayloadRow(-1);
                    prefs.setSetting("Payloads", payloads);
                }
            });
            panel_wordlist_buttons.add(button_remove);

            //Button Clear (Config Tab)
            JButton button_clear = new JButton("Clear");
            button_clear.addActionListener(e -> {
                int row = payloads.size();
                payloads.clear();
                payloadsTableModel.fireTableRowsDeleted(0,row);
                prefs.setSetting("Payloads", payloads);
            });
            panel_wordlist_buttons.add(button_clear);

            //Button Restore Defaults (Config Tab)
            JButton button_restoreDefaults = new JButton("Restore Defaults");
            button_restoreDefaults.addActionListener(e -> restoreDefaults());
            panel_wordlist_buttons.add(button_restoreDefaults);

            //Checkbox is in scope (Config Tab)
            inScopeOnly = prefs.getSetting("In Scope Only");
            if(inScopeOnly == null)inScopeOnly = true;
            checkBox_isInScope = new JCheckBox("In Scope Only", inScopeOnly);
            checkBox_isInScope.addItemListener(e -> {
                if(e.getStateChange() == ItemEvent.SELECTED) {//checkbox has been selected
                    inScopeOnly = true;
                } else {
                    inScopeOnly = false;
                }
                prefs.setSetting("In Scope Only", inScopeOnly);
            });
            panel_wordlist_buttons.add(checkBox_isInScope);
            panel_input.add(panel_wordlist_buttons);

            //Single Input Text field (Config Tab)
            JPanel panel_single_input = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JTextField textField_input = new JTextField(25);
            panel_single_input.add(textField_input);

            //Single Input Button (Config Tab)
            JButton button_add = new JButton("Add");
            button_add.addActionListener(e -> {
                String input = textField_input.getText();
                if(input != null && !input.isEmpty()){
                    int row = payloads.size();
                    payloads.add(new Payload(input, false, true));
                    payloadsTableModel.fireTableRowsInserted(row, row);
                    textField_input.setText("");
                    prefs.setSetting("Payloads", payloads);
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
            JPanel panel_responseConfig_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_clear_responses = new JButton("Clear Matches On Responses");
            button_clear_responses.addActionListener(e -> {
                synchronized (results_responses) {
                    results_responses.clear();
                    contentController.getRequestViewer().setMessage(new byte[0], true);
                    contentController.getResponseViewer().setMessage(new byte[0], false);
                    resultsTableModel_responses.fireTableDataChanged();
                }
            });
            panel_responseConfig_buttons.add(button_clear_responses);

            //Checkbox match on responses (Config Tab)
            matchOnResponses = prefs.getSetting("Match On Responses");
            if(matchOnResponses == null)matchOnResponses = true;
            checkBox_matchOnResponses = new JCheckBox("Match On Responses", matchOnResponses);
            checkBox_matchOnResponses.addItemListener(e -> {
                //checkbox has been selected
                matchOnResponses = e.getStateChange() == ItemEvent.SELECTED;
                prefs.setSetting("Match On Responses", matchOnResponses);
            });
            panel_responseConfig_buttons.add(checkBox_matchOnResponses);
            panel_input.add(panel_responseConfig_buttons);

            //Second Separator (Config Tab)
            panel_input.add(new JSeparator());

            // Request Config Label (Config Tab)
            JPanel panel_label_requests = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JLabel label_requests = new JLabel("Request Match Configuration");
            label_requests.setHorizontalAlignment(SwingConstants.CENTER);
            panel_label_requests.add(label_requests);
            panel_input.add(panel_label_requests);

            //Clear requests table Button (Config Tab)
            JPanel panel_requestConfig_buttons = new JPanel(new FlowLayout(FlowLayout.CENTER));
            JButton button_clear_requests = new JButton("Clear Matches On Requests");
            button_clear_requests.addActionListener(e -> {
                synchronized (results_requests) {
                    results_requests.clear();
                    contentController.getRequestViewer().setMessage(new byte[0], true);
                    contentController.getResponseViewer().setMessage(new byte[0], false);
                    resultsTableModel_requests.fireTableDataChanged();
                }
            });
            panel_requestConfig_buttons.add(button_clear_requests);

            //Checkbox match on responses (Config Tab)
            matchOnRequests = prefs.getSetting("Match On Requests");
            if(matchOnRequests == null)matchOnRequests = false;
            checkBox_matchOnRequests = new JCheckBox("Match On Requests", matchOnRequests);
            checkBox_matchOnRequests.addItemListener(e -> {
                //checkbox has been selected
                matchOnRequests = e.getStateChange() == ItemEvent.SELECTED;
                prefs.setSetting("Match On Requests", matchOnRequests);
            });
            panel_requestConfig_buttons.add(checkBox_matchOnRequests);
            panel_input.add(panel_requestConfig_buttons);

            // main split pane for response items (Results Tab)
            JSplitPane splitPane_results = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            JTabbedPane tabbedPane_results = new JTabbedPane();

            // Table Results Tab - Responses
            table_results_responses = new ResultTable(resultsTableModel_responses, results_responses, contentController);
            table_results_responses.setDefaultColumnSizes();
            JScrollPane scrollPane_Responses = new JScrollPane(table_results_responses);
            scrollPane_Responses.setPreferredSize(new Dimension(0,330));
            tabbedPane_results.addTab("Matches On Responses", scrollPane_Responses);

            // Table of Results Tab - Requests
            table_results_requests = new ResultTable(resultsTableModel_requests, results_requests, contentController);
            table_results_requests.setDefaultColumnSizes();
            JScrollPane scrollPane_Requests = new JScrollPane(table_results_requests);
            scrollPane_Requests.setPreferredSize(new Dimension(0,330));
            tabbedPane_results.addTab("Matches On Requests", scrollPane_Requests);
            splitPane_results.setLeftComponent(tabbedPane_results);

            //Tabbed pane with request/response viewers (Results Tab)
            JTabbedPane tabs_requestResponses = new JTabbedPane();
            contentController.setRequestViewer(ResponsePatternMatcher.callbacks.createMessageEditor(responsePatternMatcher, false));
            contentController.setResponseViewer(ResponsePatternMatcher.callbacks.createMessageEditor(responsePatternMatcher, false));
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
            if(githubLogo != null) {
                githubLogo.setPreferredSize(new Dimension(80, 50));
                panel_github.add(githubLogo);
            }
            String twitterURL="https://twitter.com/JackJarvis07";
            JHyperlink twitterLogo = new JHyperlink(new ImageIcon(getClass().getClassLoader().getResource("Twitter_Logo_Blue_42px.png")), twitterURL, twitterURL);
            if(twitterLogo != null) {
                twitterLogo.setPreferredSize(new Dimension(80, 50));
                panel_github.add(twitterLogo);
            }
            panel_about_contents.add(panel_github);

            panel_about.add(panel_about_contents);

            //Setting up the tabs
            tabs_outer = new JTabbedPane();
            tabs_outer.addTab("Config", scrollPane_input);
            tabs_outer.addTab("Matches", splitPane_results);
            tabs_outer.addTab("About", scrollPane_about);

            // customize our UI components
            ResponsePatternMatcher.callbacks.customizeUiComponent(tabs_outer);

            // add the custom tab to Burp's UI
            ResponsePatternMatcher.callbacks.addSuiteTab(responsePatternMatcher);

            // register ourselves as an HTTP listener
            ResponsePatternMatcher.callbacks.registerHttpListener(responsePatternMatcher);

            //Setup configs for first time usage
            Boolean firstRun = prefs.getSetting("First Run");
            if(firstRun == null){
                restoreDefaults();
                prefs.setSetting("First Run", false);
            }

            ResponsePatternMatcher.stdout.println("Extension Loaded Successfully");
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

    public JTabbedPane getTabs_outer(){
        return tabs_outer;
    }

    public Boolean getInScopeOnly(){
        return inScopeOnly;
    }

    public Boolean getMatchOnRequests(){
        return matchOnRequests;
    }

    public Boolean getMatchOnResponses(){
        return  matchOnResponses;
    }

    public List<Payload> getPayloads(){
        return payloads;
    }

    public List<ResultEntry> getResults_responses(){
        return results_responses;
    }

    public List<ResultEntry> getResults_requests(){
        return results_requests;
    }

    public ResultsTableModel getResultsTableModel_responses(){
        return resultsTableModel_responses;
    }

    public ResultsTableModel getResultsTableModel_requests(){
        return resultsTableModel_requests;
    }
}
