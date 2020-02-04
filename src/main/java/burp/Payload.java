package burp;

public class Payload {
    String content;
    Boolean isRegex;
    Payload(String content, Boolean isRegex){
        this.content=content;
        this.isRegex=isRegex;
    }
}
