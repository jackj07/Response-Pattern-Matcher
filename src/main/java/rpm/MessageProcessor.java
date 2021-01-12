package rpm;

import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import rpm.model.ResultsTableModel;
import rpm.ui.GUI;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageProcessor implements Runnable {
    private int toolFlag;
    private boolean messageIsRequest;
    private IHttpRequestResponse messageInfo;
    private boolean inScopeOnly;
    private boolean matchOnRequests;
    private boolean matchOnResponses;
    private List<Payload> payloads;
    private List<ResultEntry> results_responses;
    private List<ResultEntry> results_requests;
    private ResultsTableModel resultsTableModel_responses;
    private ResultsTableModel resultsTableModel_requests;

    public MessageProcessor(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo, GUI gui) {
        this.toolFlag = toolFlag;
        this.messageIsRequest = messageIsRequest;
        this.messageInfo = messageInfo;
        this.inScopeOnly = gui.getInScopeOnly();
        this.matchOnRequests = gui.getMatchOnRequests();
        this.matchOnResponses = gui.getMatchOnResponses();
        this.payloads = gui.getPayloads();
        this.results_responses = gui.getResults_responses();
        this.results_requests = gui.getResults_requests();
        this.resultsTableModel_responses = gui.getResultsTableModel_responses();
        this.resultsTableModel_requests = gui.getResultsTableModel_requests();
    }

    @Override
    public void run() {
        try {
            //Check Scope
            if (!inScopeOnly || ResponsePatternMatcher.callbacks.isInScope(new URL(messageInfo.getHttpService().toString()))) {

                //Responses
                if(!messageIsRequest && matchOnResponses){
                    String messageAsString  = new String(messageInfo.getResponse());
                    List<ResultEntry> latestResults = new ArrayList<>();
                    URL url = ResponsePatternMatcher.helpers.analyzeRequest(messageInfo).getUrl();
                    IHttpRequestResponsePersisted requestResponsePersisted = ResponsePatternMatcher.callbacks.saveBuffersToTempFiles(messageInfo);

                    for (Payload payload : payloads) {
                        if (payload.getActive()) {//Only use the payload if it is active
                            Boolean isRegex = payload.getIsRegex();
                            String payloadContent = payload.getContent();

                            if (!isRegex)payloadContent = Pattern.quote(payloadContent);//Take as literal string, not a search pattern.
                            Pattern pattern = Pattern.compile(payloadContent, Pattern.CASE_INSENSITIVE);
                            Matcher matcher = pattern.matcher(messageAsString);

                            while (matcher.find()) {
                                String extract;
                                try {
                                    extract = messageAsString.substring(matcher.start() - 30, matcher.end() + 30);
                                } catch (StringIndexOutOfBoundsException ex) {
                                    //Only want to do this when OOB Exception is thrown following Extraction.
                                    //Too much overhead to do it for every response.
                                    extract = messageAsString.substring(
                                            getMaxStartIndex(messageAsString, matcher.start(), matcher.end()),
                                            getMaxEndIndex(messageAsString, matcher.start(), matcher.end()));
                                }

                                //Update result table with a result
                                latestResults.add(new ResultEntry(
                                        0,
                                        toolFlag,
                                        url,
                                        requestResponsePersisted,
                                        extract,
                                        payload.getContent()));
                            }
                        }
                    }
                    if (latestResults.size() > 0) {
                        synchronized (results_responses) {
                            try {
                                for (ResultEntry result : latestResults) {
                                    result.setNumber(results_responses.size());
                                    results_responses.add(result);
                                    int row = results_responses.size() - 1;
                                    resultsTableModel_responses.fireTableRowsInserted(row, row);//Have to add 1 by 1 to keep model and view aligned to prevent IOOBException
                                }
                            } catch (Exception e) {
                                ResponsePatternMatcher.stderror.println("An exception occurred when adding response to Results");
                                ResponsePatternMatcher.stderror.println(e);
                                e.printStackTrace();
                            }
                        }
                    }
                }

                //Requests
                if(messageIsRequest && matchOnRequests){
                    String messageAsString = new String(messageInfo.getRequest());
                    List<ResultEntry> latestResults = new ArrayList<>();
                    URL url = ResponsePatternMatcher.helpers.analyzeRequest(messageInfo).getUrl();
                    IHttpRequestResponsePersisted requestResponsePersisted = ResponsePatternMatcher.callbacks.saveBuffersToTempFiles(messageInfo);

                    for (Payload payload : payloads) {
                        if (payload.getActive()) {//Only use the payload if it is active
                            Boolean isRegex = payload.getIsRegex();
                            String payloadContent = payload.getContent();

                            if (!isRegex)payloadContent = Pattern.quote(payloadContent);//Take as literal string, not a search pattern.
                            Pattern pattern = Pattern.compile(payloadContent, Pattern.CASE_INSENSITIVE);
                            Matcher matcher = pattern.matcher(messageAsString);

                            while (matcher.find()) {
                                String extract;
                                try {
                                    extract = messageAsString.substring(matcher.start() - 30, matcher.end() + 30);
                                } catch (StringIndexOutOfBoundsException ex) {
                                    //Only want to do this when OOB Exception is thrown following Extraction.
                                    //Too much overhead to do it for every response.
                                    extract = messageAsString.substring(
                                            getMaxStartIndex(messageAsString, matcher.start(), matcher.end()),
                                            getMaxEndIndex(messageAsString, matcher.start(), matcher.end()));
                                }

                                //Update result table with a result
                                latestResults.add(new ResultEntry(
                                        0,
                                        toolFlag,
                                        url,
                                        requestResponsePersisted,
                                        extract,
                                        payload.getContent()));
                            }
                        }
                    }
                    if (latestResults.size() > 0) {
                        synchronized (results_requests) {
                            try {
                                for (ResultEntry result : latestResults) {
                                    result.setNumber(results_requests.size());
                                    results_requests.add(result);
                                    int row = results_requests.size() - 1;
                                    resultsTableModel_requests.fireTableRowsInserted(row, row);//Have to add 1 by 1 to keep model and view aligned to prevent IOOBException
                                }
                            } catch (Exception e) {
                                ResponsePatternMatcher.stderror.println("An exception occurred when adding request to Results");
                                ResponsePatternMatcher.stderror.println(e);
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        } catch (MalformedURLException e) {
            ResponsePatternMatcher.stderror.println("A Malformed URL occurred when checking scope:");
            ResponsePatternMatcher.stderror.println(e);
            e.printStackTrace();
        } catch (Exception e){
            ResponsePatternMatcher.stderror.println("An error occurred processing message:");
            ResponsePatternMatcher.stderror.println(e);
            e.printStackTrace();
        }
    }

    //Return the start index for the extract by going back as far as you can whilst staying within bounds of response
    private int getMaxStartIndex(String response, int extractStartIndex, int extractEndIndex) {
        int toReturn = 0;
        try {
            while (true) {
                response.substring(extractStartIndex + toReturn - 1, extractEndIndex);
                toReturn--;
                if (toReturn <= -25) break;
            }
        } catch (StringIndexOutOfBoundsException ex) { }
        return extractStartIndex + toReturn;
    }

    //Return the start index for the extract by going forward as far as you can whilst staying within bounds of response
    private int getMaxEndIndex(String response, int extractStartIndex, int extractEndIndex) {
        int toReturn = 0;
        try {
            while (true) {
                response.substring(extractStartIndex, extractEndIndex + toReturn + 1);
                toReturn++;
                if (toReturn >= 25) break;
            }
        } catch (StringIndexOutOfBoundsException ex) { }
        return extractEndIndex + toReturn;
    }
}
