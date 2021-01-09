package rpm.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import rpm.ResultEntry;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class JSONParser {
    ObjectMapper mapper;
    IBurpExtenderCallbacks callbacks;

    public JSONParser(IBurpExtenderCallbacks callbacks){
        mapper = new ObjectMapper();
        this.callbacks = callbacks; //so you can pass in mock for testing
    }

    public void writeResultsToFile(File file, ArrayList<ResultEntry>results){
        try {
            ArrayNode rootNode = mapper.createArrayNode();
            for (ResultEntry result : results){
                ObjectNode resultObject = mapper.createObjectNode();

                resultObject.put("Number", result.getNumber());
                resultObject.put("Tool", callbacks.getToolName(result.getTool()));
                resultObject.put("URL", result.getUrl().toString());

                ObjectNode requestResponse = mapper.createObjectNode();
                requestResponse.put("Request", new String(result.getRequestResponse().getRequest()));
                requestResponse.put("Response", new String(result.getRequestResponse().getResponse()));
                resultObject.set("HTTP Contents", requestResponse);

                resultObject.put("Sample Extract", result.getSampleExtract());
                resultObject.put("Payload Content", result.getPayloadContent());

                rootNode.add(resultObject);
            }
            //Pretty print to file
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, rootNode);
        }catch (IOException ex){
            BurpExtender.stderror.println("An exception occurred when exporting results to file:");
            BurpExtender.stderror.println(ex);
            ex.printStackTrace();
        } catch (Exception e2){
            BurpExtender.stderror.println("An error occurred parsing JSON:");
            BurpExtender.stderror.println(e2);
            e2.printStackTrace();
        }
    }
}
