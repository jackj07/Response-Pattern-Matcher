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
    private List<Payload> payloads;
    private List<ResultEntry> results;
    private ResultsTableModel resultsTableModel;

    public MessageProcessor(int toolFlag, IHttpRequestResponse messageInfo,
                            boolean inScopeOnly, boolean messageIsRequest,
                            List<Payload> payloads,
                            List<ResultEntry> results,
                            ResultsTableModel resultsTableModel) {
        this.toolFlag = toolFlag;
        this.messageInfo = messageInfo;
        this.inScopeOnly = inScopeOnly;
        this.messageIsRequest = messageIsRequest;
        this.payloads = payloads;
        this.results = results;
        this.resultsTableModel = resultsTableModel;
    }

    @Override
    public void run() {
        if (!messageIsRequest) {
            // Check for scope
            try {
                if ((inScopeOnly && BurpExtender.callbacks.isInScope(new URL(messageInfo.getHttpService().toString()))) || !inScopeOnly) {
                    // create a new log entry with the message details
                    String responseAsString = new String(messageInfo.getResponse());

                    List<ResultEntry> latestResults = new ArrayList<ResultEntry>();
                    URL url = BurpExtender.helpers.analyzeRequest(messageInfo).getUrl();
                    IHttpRequestResponsePersisted responsePersisted = BurpExtender.callbacks.saveBuffersToTempFiles(messageInfo);

                    for (Payload payload : payloads) {
                        if(payload.active) {//Only use the payload if it is active
                            Boolean isRegex = payload.isRegex;
                            String payloadContent = payload.content;

                            if (!isRegex)
                                payloadContent = Pattern.quote(payloadContent);//Take as literal string, not a search pattern.
                            Pattern pattern = Pattern.compile(payloadContent, Pattern.CASE_INSENSITIVE);
                            Matcher matcher = pattern.matcher(responseAsString);

                            while (matcher.find()) {
                                String extract = "";
                                try {
                                    extract = responseAsString.substring(matcher.start() - 30, matcher.end() + 30);
                                } catch (StringIndexOutOfBoundsException ex) {
                                    //Only want to do this when OOB Exception is thrown following Extraction.
                                    //Too much overhead to do it for every response.
                                    extract = responseAsString.substring(
                                            getMaxStartIndex(responseAsString, matcher.start(), matcher.end()),
                                            getMaxEndIndex(responseAsString, matcher.start(), matcher.end()));
                                }

                                //Update result table with a result
                                latestResults.add(new ResultEntry(
                                        0,
                                        toolFlag,
                                        url,
                                        responsePersisted,
                                        extract,
                                        payload.content));
                            }
                        }
                    }
                    if (latestResults.size() > 0) {
                        synchronized (results) {
                            try {
                                for (ResultEntry result : latestResults) {
                                    result.number = results.size();
                                    results.add(result);
                                    int row = results.size() - 1;
                                    resultsTableModel.fireTableRowsInserted(row, row);//Have to add 1 by 1 to keep model and view aligned to prevent IOOBException
                                }
                            }catch(Exception e){
                                BurpExtender.sterror.println("An exception occurred when adding Results");
                                e.printStackTrace();
                            }
                        }
                    }
                }
            } catch (MalformedURLException e) {
                BurpExtender.sterror.println("A Malformed URL occurred");
                BurpExtender.sterror.println(e);
            }
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
