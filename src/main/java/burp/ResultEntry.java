package burp;

import java.net.URL;

public class ResultEntry
{
    int number;
    final int tool;
    final URL url;
    final IHttpRequestResponsePersisted requestResponse;
    final String sampleExtract;
    final String payloadContent;

    ResultEntry(int number, int tool, URL url, IHttpRequestResponsePersisted requestResponse,
                String sampleExtract, String payloadContent)
    {
        this.number = number;
        this.tool = tool;
        this.url = url;
        this.requestResponse = requestResponse;
        this.sampleExtract = sampleExtract;
        this.payloadContent = payloadContent;
    }
}
