package burp;

import org.junit.jupiter.api.Test;

import java.awt.*;
import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void JacksonParserTest() {
        //Quick and dirty Jackson test to make sure sample results are printed to a local json file
        Exception ex = null;
        try {
            ResultEntry result1 = new ResultEntry(1, 1, new URL("http://test.com"), null, "/body> password is <b>welc0me1</b>", "password");
            ResultEntry result2 = new ResultEntry(2, 1, new URL("https://github.com/"), null, "/body> username is <b>jack123</b>", "username");
            ResultEntry result3 = new ResultEntry(3, 1, new URL("https://www.lipsum.com/"), null, "port:3234", "port");
            ResultEntry result4 = new ResultEntry(4, 1, new URL("http://test2.com"), null, "/body> password is <b>welc0me2</b>", "password");
            ResultEntry result5 = new ResultEntry(5, 1, new URL("http://test3.com"), null, "asdasdsdfSDFAHtempsdgdg", "temp");

            File output = new File("C:\\Users\\consultant\\Response Pattern Matcher\\out\\test\\output.json");

            ArrayList<ResultEntry> results = new ArrayList<>(Arrays.asList(result1, result2, result3, result4, result5));

            JSONParser parser = new JSONParser();
            parser.writeResultsToFile(output, results);
        } catch (Exception e) {
            ex = e;
        }

        assertEquals(null, ex);
    }
}