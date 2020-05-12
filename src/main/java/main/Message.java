package main;

public class Message {

    private String from;
    private String to;
    private String message;
    private String datetime;

    public Message(String from, String to, String message, String datetime) {
        this.from = from;
        this.to = to;
        this.message = message;
        this.datetime = datetime;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getDatetime() {
        return datetime;
    }

    public void setDatetime(String datetime) {
        this.datetime = datetime;
    }
}
