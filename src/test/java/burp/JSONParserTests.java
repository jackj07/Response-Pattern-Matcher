package burp;

import org.junit.jupiter.api.Test;
import rpm.ResultEntry;
import rpm.ui.JSONParser;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JSONParserTests {
    @Test
    void JacksonParserTest(){
        //Jackson test to make sure sample results are printed to a local json file correctly
        Exception ex = null;
        try {
            ResultEntry result1 = new ResultEntry(1, 1, new URL("http://test.com"), requestResponsePersisted, "/body> password is <b>welc0me1</b>", "password");
            ResultEntry result2 = new ResultEntry(2, 1, new URL("https://github.com/"), requestResponsePersisted, "/body> username is <b>jack123</b>", "username");
            ResultEntry result3 = new ResultEntry(3, 2, new URL("https://www.lipsum.com/"), requestResponsePersisted, "port:3234", "port");
            ResultEntry result4 = new ResultEntry(4, 3, new URL("http://test2.com"), requestResponsePersisted, "/body> password is <b>welc0me2</b>", "password");
            ResultEntry result5 = new ResultEntry(5, 1, new URL("http://test3.com"), requestResponsePersisted, "asdasdsdfSDFAHtempsdgdg", "temp");

            File output = new File("Z:\\Projects\\GitProjects_Working\\Response Pattern Matcher\\out\\test\\resources\\output.json");
            //File output = new File("/Users/benson/Response-Pattern-Matcher/src/test/resources/output.json");

            ArrayList<ResultEntry> results = new ArrayList<>(Arrays.asList(result1, result2, result3, result4, result5));

            IBurpExtenderCallbacks mockCallbacks = mock(IBurpExtenderCallbacks.class);

            JSONParser parser = new JSONParser(mockCallbacks);

            when(mockCallbacks.getToolName(result1.getTool())).thenReturn("intruder");
            when(mockCallbacks.getToolName(result2.getTool())).thenReturn("intruder");
            when(mockCallbacks.getToolName(result3.getTool())).thenReturn("proxy");
            when(mockCallbacks.getToolName(result4.getTool())).thenReturn("repeater");
            when(mockCallbacks.getToolName(result5.getTool())).thenReturn("proxy");

            parser.writeResultsToFile(output, results);
        } catch (Exception e) {
            ex = e;
        }

        assertNull(ex);
    }

    private final IHttpRequestResponsePersisted requestResponsePersisted = new IHttpRequestResponsePersisted() {
        @Override
        public void deleteTempFiles() {

        }

        @Override
        public byte[] getRequest() {
            return new byte[0];
        }

        @Override
        public void setRequest(byte[] bytes) {

        }

        @Override
        public byte[] getResponse() {
            return new byte[0];
        }

        @Override
        public void setResponse(byte[] bytes) {

        }

        @Override
        public String getComment() {
            return null;
        }

        @Override
        public void setComment(String s) {

        }

        @Override
        public String getHighlight() {
            return null;
        }

        @Override
        public void setHighlight(String s) {

        }

        @Override
        public IHttpService getHttpService() {
            return null;
        }

        @Override
        public void setHttpService(IHttpService iHttpService) {

        }

        @Override
        public String getHost() {
            return null;
        }

        @Override
        public int getPort() {
            return 0;
        }

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public void setHost(String s) {

        }

        @Override
        public void setPort(int i) {

        }

        @Override
        public void setProtocol(String s) {

        }

        @Override
        public URL getUrl() {
            return null;
        }

        @Override
        public short getStatusCode() {
            return 0;
        }
    };
}
