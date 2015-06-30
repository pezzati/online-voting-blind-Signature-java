import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.Date;

public class Voter {
    BigInteger ID;
    SecretKey key;
    BigInteger Nonce;
    Long time;
    int ks;
    boolean voted;
    boolean key_seted;
    long dis;
    long minDis;

    public Voter(BigInteger ID) {
        this.ID = ID;
        Date date = new Date();
        time = date.getTime();
        dis = Long.valueOf(Integer.valueOf(5 * 60 * 1000));
        minDis = 2000;
        voted = false;
        key_seted = false;
    }

    public void setKey(SecretKey key) {
        this.key = key;
        ks = key.hashCode();
        key_seted = true;
    }

    public void resetTime(){
        Date date = new Date();
        time = date.getTime();
    }

    public boolean canTalk(){
        Date date = new Date();
        long now = date.getTime();
        if(this.time + this.dis <= now)
            return false;
        return true;
    }

    public boolean canVote(){
        if(voted)
            return false;
        Date date = new Date();
        long now = date.getTime();
        if(now - this.time <= minDis)
            return true;
        if(this.time + this.dis >= now)
            return false;
        return true;
    }

    public void setNonce(BigInteger nonce) {
        Nonce = nonce;
    }

    public void setVoted(boolean voted) {
        this.voted = voted;
    }

    public BigInteger getID() {
        return ID;
    }

    public SecretKey getKey() {
        return key;
    }

    public BigInteger getNonce() {
        return Nonce;
    }

    public int getKs() {
        return ks;
    }
}
