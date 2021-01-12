package rpm;

import burp.IHttpRequestResponsePersisted;

import java.awt.*;
import java.net.URL;

public class ResultEntry {
    //Needs to be in serializable (Setter getter) format for Jackson json parser
    private int number;
    private int tool;
    private URL url;
    private IHttpRequestResponsePersisted requestResponse;
    private String sampleExtract;
    private String payloadContent;
    private Color color;

    public ResultEntry(int number, int tool, URL url, IHttpRequestResponsePersisted requestResponse,
                       String sampleExtract, String payloadContent) {
        this.number = number;
        this.tool = tool;
        this.url = url;
        this.requestResponse = requestResponse;
        this.sampleExtract = sampleExtract;
        this.payloadContent = payloadContent;
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    public int getTool() {
        return tool;
    }

    public void setTool(int tool) {
        this.tool = tool;
    }

    public URL getUrl() {
        return url;
    }

    public void setUrl(URL url) {
        this.url = url;
    }

    public IHttpRequestResponsePersisted getRequestResponse() {
        return requestResponse;
    }

    public void setRequestResponse(IHttpRequestResponsePersisted requestResponse) {
        this.requestResponse = requestResponse;
    }

    public String getSampleExtract() {
        return sampleExtract;
    }

    public void setSampleExtract(String sampleExtract) {
        this.sampleExtract = sampleExtract;
    }

    public String getPayloadContent() {
        return payloadContent;
    }

    public void setPayloadContent(String payloadContent) {
        this.payloadContent = payloadContent;
    }

    public Color getColor() {
        return color;
    }

    public void setColor(Color color) {
        this.color = color;
    }
}
