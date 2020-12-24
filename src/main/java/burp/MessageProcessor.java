package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageProcessor implements Runnable {
    private int toolFlag;
    private IHttpRequestResponse messageInfo;
    private boolean inScopeOnly;
    private boolean messageIsRequest;
    private boolean matchOnRequests;
    private boolean matchOnResponses;
    private List<Payload> payloads;
    private List<ResultEntry> results_responses;
    private List<ResultEntry> results_requests;
    private ResultsTableModel resultsTableModel_responses;
    private ResultsTableModel resultsTableModel_requests;

    public MessageProcessor(int toolFlag, IHttpRequestResponse messageInfo,
                            boolean inScopeOnly, boolean messageIsRequest,
                            boolean matchOnRequests, boolean matchOnResponses,
                            List<Payload> payloads,
                            List<ResultEntry> results_responses,
                            List<ResultEntry> results_requests,
                            ResultsTableModel resultsTableModel_responses,
                            ResultsTableModel resultsTableModel_requests) {
        this.toolFlag = toolFlag;
        this.messageInfo = messageInfo;
        this.inScopeOnly = inScopeOnly;
        this.messageIsRequest = messageIsRequest;
        this.matchOnRequests = matchOnRequests;
        this.matchOnResponses = matchOnResponses;
        this.payloads = payloads;
        this.results_responses = results_responses;
        this.results_requests = results_requests;
        this.resultsTableModel_responses = resultsTableModel_responses;
        this.resultsTableModel_requests = resultsTableModel_requests;
    }

    @Override
    public void run() {
        try {
            if ((inScopeOnly && BurpExtender.callbacks.isInScope(new URL(messageInfo.getHttpService().toString()))) || !inScopeOnly) { //check scope

                String messageAsString = null;
                if(!messageIsRequest && matchOnResponses){
                    messageAsString  = new String(messageInfo.getResponse());
                }else if(messageIsRequest && matchOnRequests){
                    messageAsString = new String(messageInfo.getRequest());
                }else{
                    return;
                }

                List<ResultEntry> latestResults = new ArrayList<ResultEntry>();
                URL url = BurpExtender.helpers.analyzeRequest(messageInfo).getUrl();
                IHttpRequestResponsePersisted requestResponsePersisted = BurpExtender.callbacks.saveBuffersToTempFiles(messageInfo);

                for (Payload payload : payloads) {
                    if (payload.active) {//Only use the payload if it is active
                        Boolean isRegex = payload.isRegex;
                        String payloadContent = payload.content;

                        if (!isRegex)
                            payloadContent = Pattern.quote(payloadContent);//Take as literal string, not a search pattern.
                        Pattern pattern = Pattern.compile(payloadContent, Pattern.CASE_INSENSITIVE);
                        Matcher matcher = pattern.matcher(messageAsString);

                        while (matcher.find()) {
                            String extract = "";
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
                                    payload.content));
                        }
                    }
                }
                if ((latestResults.size() > 0) && !messageIsRequest) {
                    synchronized (results_responses) {
                        try {
                            for (ResultEntry result : latestResults) {
                                result.setNumber(results_responses.size());
                                results_responses.add(result);
                                int row = results_responses.size() - 1;
                                resultsTableModel_responses.fireTableRowsInserted(row, row);//Have to add 1 by 1 to keep model and view aligned to prevent IOOBException
                            }
                        } catch (Exception e) {
                            BurpExtender.sterror.println("An exception occurred when adding response to Results");
                            BurpExtender.sterror.println(e);
                            e.printStackTrace();
                        }
                    }
                }else if ((latestResults.size() > 0) && messageIsRequest) {
                    synchronized (results_requests) {
                        try {
                            for (ResultEntry result : latestResults) {
                                result.setNumber(results_requests.size());
                                results_requests.add(result);
                                int row = results_requests.size() - 1;
                                resultsTableModel_requests.fireTableRowsInserted(row, row);//Have to add 1 by 1 to keep model and view aligned to prevent IOOBException
                            }
                        } catch (Exception e) {
                            BurpExtender.sterror.println("An exception occurred when adding request to Results");
                            BurpExtender.sterror.println(e);
                            e.printStackTrace();
                        }
                    }
                }
            }
        } catch (MalformedURLException e) {
            BurpExtender.sterror.println("A Malformed URL occurred when checking scope");
            BurpExtender.sterror.println(e);
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
        } catch (StringIndexOutOfBoundsException ex) {
        }
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
        } catch (StringIndexOutOfBoundsException ex) {
        }
        return extractEndIndex + toReturn;
    }
}
