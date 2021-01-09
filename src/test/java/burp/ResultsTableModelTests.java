package burp;

import org.junit.jupiter.api.Test;
import rpm.Payload;
import rpm.ResultEntry;
import rpm.model.ResultsTableModel;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ResultsTableModelTests {
    @Test
    void resultsTableModel_getValueAtMethodReturnsCorrectItem(){
        Exception ex = null;

        try {
            ResultEntry result1 = new ResultEntry(1, 1, new URL("http://test.com"), requestResponsePersisted, "/body> password is <b>welc0me1</b>", "password");
            ResultEntry result2 = new ResultEntry(2, 1, new URL("https://github.com/"), requestResponsePersisted, "/body> username is <b>jack123</b>", "username");
            ResultEntry result3 = new ResultEntry(3, 2, new URL("https://www.lipsum.com/"), requestResponsePersisted, "port:3234", "port");
            ResultEntry result4 = new ResultEntry(4, 3, new URL("http://test2.com"), requestResponsePersisted, "/body> password is <b>welc0me2</b>", "password");
            ResultEntry result5 = new ResultEntry(5, 1, new URL("http://test3.com"), requestResponsePersisted, "asdasdsdfSDFAHtempsdgdg", "temp");

            ArrayList<ResultEntry> results = new ArrayList<>(Arrays.asList(result1, result2, result3, result4, result5));

            ResultsTableModel resultsTableModelTableModel = new ResultsTableModel(results);

            assertEquals(1, resultsTableModelTableModel.getValueAt(0,0));
            assertEquals("https://github.com/", resultsTableModelTableModel.getValueAt(1,2).toString());
            assertEquals("port", resultsTableModelTableModel.getValueAt(2,3));
            assertEquals("/body> password is <b>welc0me2</b>", resultsTableModelTableModel.getValueAt(3,4));
        }catch (Exception e){
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
            return "Test Comment";
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
