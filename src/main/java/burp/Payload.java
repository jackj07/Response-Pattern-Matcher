package burp;

public class Payload {
    String content;
    Boolean isRegex;
    Boolean active;
    Payload(String content, Boolean isRegex, Boolean active){
        this.content=content;
        this.isRegex=isRegex;
        this.active = active;
    }
}
