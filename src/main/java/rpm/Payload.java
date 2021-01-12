package rpm;

public class Payload {
    private String content;
    private Boolean isRegex;
    private Boolean active;

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
