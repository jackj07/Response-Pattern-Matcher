package burp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class JSONParser {
    ObjectMapper mapper;

    public JSONParser(){
        mapper = new ObjectMapper();
    }

    public void writeResultsToFile(File file, ArrayList<ResultEntry>results){
        try {
            ArrayNode rootNode = mapper.createArrayNode();
            for (ResultEntry result : results){
                ObjectNode resultObject = mapper.createObjectNode();

                resultObject.put("Number", result.getNumber());
                resultObject.put("Tool", BurpExtender.callbacks.getToolName(result.getTool()));
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
            BurpExtender.sterror.println("An exception occurred when exporting results to file:");
            BurpExtender.sterror.println(ex);
            ex.printStackTrace();
        }
    }
}
