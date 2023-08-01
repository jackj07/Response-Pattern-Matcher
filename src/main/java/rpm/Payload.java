package rpm;

public class Payload {
    private final String content;
    private final Boolean isRegex;
    private final Boolean active;

    public Payload(String content, Boolean isRegex, Boolean active){
        this.content=content;
        this.isRegex=isRegex;
        this.active = active;
    }

    public String getContent(){
        return content;
    }

    public Boolean getIsRegex(){
        return isRegex;
    }

    public Boolean getActive(){
        return active;
    }
}
