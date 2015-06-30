import java.io.Serializable;
import java.security.PublicKey;
import java.security.Timestamp;
import java.util.Date;

public class log implements Serializable{
    byte[] msg;
    String time;
    String sender;
    String receiver;
    PublicKey ua_pub_key;

    public log(byte[] msg, String sender, String receiver) {
        this.msg = msg;
        time = String.valueOf(new Date().getTime());
        this.sender = sender;
        this.receiver = receiver;
    }


    public PublicKey getUa_pub_key() {
        return ua_pub_key;
    }

    public void setUa_pub_key(PublicKey ua_pub_key) {
        this.ua_pub_key = ua_pub_key;
    }

    public byte[] getMsg() {
        return msg;
    }

    public void setMsg(byte[] msg) {
        this.msg = msg;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getReceiver() {
        return receiver;
    }

    public void setReceiver(String receiver) {
        this.receiver = receiver;
    }
}
