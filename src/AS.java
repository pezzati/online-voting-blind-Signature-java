import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;

/**
 * Created by peyman on 6/27/15.
 */
public class AS {
    public static final String Algorithm = "RSA";
    public static final long beginTime = 3000;
    public static final long EndTime = 0;
    public static SecretKey key_vs;
    public static ArrayList<Voter> voters;
    public static long dis;
    public static int ks_vs;
    public static loger loger;

    public static void main(String[] args) {
        loger = new loger("ASLog");
        voters = new ArrayList<Voter>();
        dis = Long.valueOf(Integer.valueOf(5 * 60 * 1000));
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey priv = keyPair.getPrivate();
            PublicKey pub = keyPair.getPublic();

            Socket socket = new Socket("localhost", 8080);


            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            outputStream.writeObject(pub);
            System.out.println("Public key sent to VS");

            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            PublicKey pub_vs = (PublicKey) objectInputStream.readObject();
            System.out.println("Public key of VS received");

            SecureRandom random = new SecureRandom();
            BigInteger N = new BigInteger(32, 50, random);
            String n = N.toString();

            Date date = new Date();
            String time = String.valueOf(date.getTime());

            String m = n + " " +  time;

            createLog(new log(m.getBytes(), "AS", "VS"));

            byte[] hashed = encrypt_priv(hash(m.getBytes()), priv);


            byte[] all = new byte[152];
            for(int i = 0; i < 152; i++){
                if(i < 24)
                    all[i] = m.getBytes()[i];
                else
                    all[i] = hashed[i - 24];
            }
            sendBigBytes(all, socket, pub_vs);

            while (true){
                byte[] msg = readBytes(socket);
                byte[] msg1 = new byte[128];
                byte[] msg2 = new byte[128];
                for(int i = 0; i < 128; i++)
                    msg1[i] = msg[i];
                for(int i = 0; i < 128; i++)
                    msg2[i] = msg[i + 128];
                byte[] dec_msg1 = decrypt_priv_toByte(msg1, priv);
                byte[] dec_msg2 = decrypt_priv_toByte(msg2, priv);

                byte[] all_dec = new byte[67 + 128];

                for (int i = 0; i < 195; i++){
                    if(i < dec_msg1.length)
                        all_dec[i] = dec_msg1[i];
                    else
                        all_dec[i] = dec_msg2[i - dec_msg1.length];
                }

                byte[] m_byte = new byte[67];
                byte[] hashed_geted = new byte[128];

                for(int i = 0; i < 195; i++){
                    if (i < 67)
                        m_byte[i] = all_dec[i];
                    else
                        hashed_geted[i - 67] = all_dec[i];
                }


                byte[] bt = new byte[32];
                for(int i = 0; i < 32; i++)
                    bt[i] = m_byte[i];
                byte[] content = new byte[35];
                for(int i = 0; i < 35; i++)
                    content[i] = m_byte[i + 32];

                String M = new String(content);
                createLog(new log(m_byte, "VS", "AS"));

                if(!timeIsOk(Long.valueOf(M.split("[ ]")[2]), beginTime, EndTime))
                    continue;
                if(!checkHash(m_byte, hashed_geted, pub_vs))
                    continue;

                if(!(new BigInteger(M.split("[ ]")[0]).equals(N))){
                    System.out.println("Packet dropped because of N_as error");
                    continue;
                }

                BigInteger N_vs = new BigInteger(M.split("[ ]")[1]);

                //Key session between AS-VS is set now
                key_vs = new SecretKeySpec(bt, "AES");
                ks_vs = key_vs.hashCode();
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key_vs);

                String m_last_str = N_vs.toString() + " " + String.valueOf(date.getTime());
                createLog(new log(m_last_str.getBytes(), "AS", "VS"));
                byte[] last_hash = hash(m_last_str.getBytes());

                byte[] doFinalByte = new byte[m_last_str.getBytes().length + last_hash.length];
                for(int i = 0; i < doFinalByte.length; i++){
                    if(i < m_last_str.getBytes().length)
                        doFinalByte[i] = m_last_str.getBytes()[i];
                    else
                        doFinalByte[i] = last_hash[i - m_last_str.getBytes().length];
                }

                byte[] finalLastMsg = cipher.doFinal(doFinalByte);
                sendBytes(socket, finalLastMsg);

                break;
            }


            //Wait for UA
            ServerSocket server = new ServerSocket(8081);
            while (true){
                System.out.println("here2");
                Socket ua_socket = server.accept();

                System.out.println("here");

                ObjectInputStream objectInputStream_ua = new ObjectInputStream(ua_socket.getInputStream());
                PublicKey pub_ua = (PublicKey) objectInputStream_ua.readObject();
                System.out.println("Public key of UA received");

                ObjectOutputStream outputStream_ua = new ObjectOutputStream(ua_socket.getOutputStream());
                outputStream_ua.writeObject(pub);
                System.out.println("Public key sent to UA");

                byte[] auth_msg = readBytes(ua_socket);
                System.out.println("furst msg from AS rec");
                byte[] msg1 = new byte[128];
                byte[] msg2 = new byte[128];
                for(int i = 0; i < 128; i++)
                    msg1[i] = auth_msg[i];
                for(int i = 0; i < 128; i++)
                    msg2[i] = auth_msg[i + 128];
                byte[] dec_msg1 = decrypt_priv_toByte(msg1, priv);
                byte[] dec_msg2 = decrypt_priv_toByte(msg2, priv);

                byte[] all_dec = new byte[dec_msg1.length + dec_msg2.length];

                for (int i = 0; i < all_dec.length; i++){
                    if(i < dec_msg1.length)
                        all_dec[i] = dec_msg1[i];
                    else
                        all_dec[i] = dec_msg2[i - dec_msg1.length];
                }

                byte[] m_byte = new byte[all_dec.length - 128];
                byte[] hashed_geted = new byte[128];

                for(int i = 0; i < all_dec.length; i++){
                    if (i < m_byte.length)
                        m_byte[i] = all_dec[i];
                    else
                        hashed_geted[i - m_byte.length] = all_dec[i];
                }

                if(!checkHash(m_byte, hashed_geted, pub_ua)){
                    ua_socket.close();
                    continue;
                }
                String M = new String(m_byte);


                if(!timeIsOk(Long.valueOf(M.split("[ ]")[2]), beginTime, EndTime)){
                    ua_socket.close();
                    continue;
                }

                log log1 = new log(m_byte, "UA", "AS");
                log1.setUa_pub_key(pub_ua);
                createLog(log1);

                String IDua = M.split("[ ]")[0];
                Voter voter;
                if(isVoterExist(new BigInteger(IDua)))
                    voter = getVoter(new BigInteger(IDua));
                else{
                    voter = new Voter(new BigInteger(IDua));
                }
                if(voter.voted)
                    continue;
                if(!voter.canVote())
                    continue;



                voters.add(voter);
                String N_ua = M.split("[ ]")[1];

                //Set session key
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
                SecretKey key_ua = keyGenerator.generateKey();
                voter.setKey(key_ua);


                byte[] key_ua_bt = key_ua.getEncoded();

                String n_as = nonce();

                String send_key_to_ua = N_ua + " " + n_as + " " + timenow();




                byte[] msg_m_B = new byte[key_ua_bt.length + send_key_to_ua.getBytes().length];
                for(int i = 0; i < msg_m_B.length; i++){
                    if(i < key_ua_bt.length)
                        msg_m_B[i] = key_ua_bt[i];
                    else
                        msg_m_B[i] = send_key_to_ua.getBytes()[i - key_ua_bt.length];
                }
                //System.out.println("M.size: " + msg_m_B.length);
                log log2 = new log(msg_m_B, "AS", "UA");
                log2.setUa_pub_key(pub_ua);
                createLog(log2);



                byte[] send_hashed = encrypt_priv(hash(msg_m_B), priv);

                byte[] send_m_b = new byte[msg_m_B.length + send_hashed.length];
                for(int i = 0; i < send_m_b.length; i++){
                    if(i < msg_m_B.length)
                        send_m_b[i] = msg_m_B[i];
                    else
                        send_m_b[i] = send_hashed[i - msg_m_B.length];
                }

                sendBigBytes(send_m_b, ua_socket, pub_ua);


                byte[] decBlindedMsgWithHash = readBytes(ua_socket);
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key_ua);
                byte[] blindedMsgWithHash = cipher.doFinal(decBlindedMsgWithHash);
                byte[] blindedMsg = new byte[blindedMsgWithHash.length - 16];
                byte[] hashMsg = new byte[16];
                for(int i = 0; i < blindedMsgWithHash.length; i++){
                    if(i < blindedMsg.length)
                        blindedMsg[i] = blindedMsgWithHash[i];
                    else
                        hashMsg[i - blindedMsg.length] = blindedMsgWithHash[i];
                }

                if(!checkHash(blindedMsg, hashMsg))
                    continue;
                String blinded_str = new String(blindedMsg);
                if(!timeIsOk(Long.valueOf(blinded_str.split("[ ]")[2]), beginTime, EndTime))
                    continue;
                BigInteger id_str = new BigInteger(blinded_str.split("[ ]")[0]);

                log log3 = new log(blinded_str.getBytes(), "UA", "AS");
                log3.setUa_pub_key(pub_ua);
                createLog(log3);

                if(!isVoterExist(id_str)){
                    System.out.println("not exist");
                    continue;
                }
                if(!getVoter(id_str).getID().equals(voter.getID())){
                    System.out.println("not equal");
                    continue;
                }
                if(!voter.canTalk()){
                    System.out.println("more than 5 min");
                    continue;
                }

                if(!blinded_str.split("[ ]")[1].equals(n_as)){
                    System.out.println("n_as is not same");
                    continue;
                }


                // must sign blinded message and send it to UA.
                BigInteger modulus = ((RSAPrivateKey)priv).getModulus();
                BigInteger priv_exponent = ((RSAPrivateKey)priv).getPrivateExponent();
                BigInteger blinded_message_int = new BigInteger(blinded_str.split("[ ]")[3]);
                BigInteger signed_blinded_message = blinded_message_int.modPow(priv_exponent, modulus);

                voter.setNonce(new BigInteger(nonce()));
                int seq_number = voter.getKs();
                seq_number++;
                voter.ks = seq_number;

                String signed_vote = signed_blinded_message.toString() + " " + voter.getNonce().toString() + " " + seq_number + " " + timenow();
                byte[] hash_signed_vote = hash(signed_vote.getBytes());
                byte[] signed_vote_to_send = new byte[signed_vote.getBytes().length + hash_signed_vote.length];
                System.arraycopy(signed_vote.getBytes(), 0, signed_vote_to_send, 0, signed_vote.getBytes().length);
                System.arraycopy(hash_signed_vote, 0, signed_vote_to_send, signed_vote.getBytes().length, hash_signed_vote.length);

                log log4 = new log(signed_vote.getBytes(), "AS", "UA");
                log4.setUa_pub_key(pub_ua);
                createLog(log4);


                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key_ua);
                byte[] signed_vote_encrypted = cipher.doFinal(signed_vote_to_send);
                sendBytes(ua_socket, signed_vote_encrypted);
                // Blinded Signed Message sent to UA. waiting for vote confirmation.


                while(true){
                    byte[] encReportWithHash = readBytes(socket);
                    cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, key_vs);
                    byte[] reportWithHash = cipher.doFinal(encReportWithHash);

                    byte[] report = new byte[reportWithHash.length - 16];
                    byte[] hashReport = new byte[16];
                    for(int i = 0; i < reportWithHash.length; i++){
                        if(i < report.length)
                            report[i] = reportWithHash[i];
                        else
                            hashReport[i - report.length] = reportWithHash[i];
                    }


                    if(!checkHash(report, hashReport))
                        continue;

                    String report_str = new String(report);
                    if(!timeIsOk(Long.valueOf(report_str.split("[ ]")[3]), beginTime, EndTime))
                        continue;
                    if(Integer.valueOf(report_str.split("[ ]")[2]) != (ks_vs + 1))
                        continue;
                    ks_vs++;

                    log log = new log(report, "UA", "AS");
                    log.setUa_pub_key(pub_ua);
                    createLog(log);

                    Voter my_voter = null;
                    BigInteger IDreport = new BigInteger(report_str.split("[ ]")[1]);
                    int rep = Integer.valueOf(report_str.split("[ ]")[0]);
                    for(int i = 0; i < voters.size(); i++){
                        if(voters.get(i).getNonce().equals(IDreport)){
                            my_voter = voters.get(i);
                            my_voter.voted = true;
                        }
                    }

                    if(my_voter == null)
                        continue;;


                    ks_vs++;
                    String report_vs = IDreport.toString() + " " + ks_vs + " " + timenow();
                    byte[] hash_rep = hash(report_vs.getBytes());
                    byte[] rep_vs = new byte[report_vs.getBytes().length + hash_rep.length];
                    System.arraycopy(report_vs.getBytes(), 0, rep_vs, 0, report_vs.getBytes().length);
                    System.arraycopy(hash_rep, 0, rep_vs, report_vs.getBytes().length, hash_rep.length);

                    createLog(new log(report_vs.getBytes(), "AS", "VS"));


                    cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, key_vs);
                    byte[] final_to_vs = cipher.doFinal(rep_vs);
                    sendBytes(socket, final_to_vs);



                    String report_ua = rep + " " + (my_voter.getKs()+2) + " " + timenow();
                    byte[] hash_rep_ua = hash(report_ua.getBytes());
                    byte[] rep_ua_to_send = new byte[report_ua.getBytes().length + hash_rep_ua.length];
                    System.arraycopy(report_ua.getBytes(), 0, rep_ua_to_send, 0, report_ua.getBytes().length);
                    System.arraycopy(hash_rep_ua, 0, rep_ua_to_send, report_ua.getBytes().length, hash_rep_ua.length);

                    log log6 = new log(report_ua.getBytes(), "AS", "UA");
                    log6.setUa_pub_key(pub_ua);
                    createLog(log6);

                    cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, key_ua);
                    byte[] final_to_ua = cipher.doFinal(rep_ua_to_send);
                    sendBytes(ua_socket, final_to_ua);



                    ua_socket.close();
                    outputStream_ua.close();
                    objectInputStream_ua.close();
                    break;
                }



            }



        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private static void createLog(log log) {
        loger.createlog(log);
    }


    public static Voter getVoter(BigInteger id){
        if(isVoterExist(id)){
            for(int i = 0; i < voters.size(); i++){
                if(voters.get(i).getID().equals(id))
                    return voters.get(i);
            }
        }
        return null;
        /*Voter voter = new Voter(id);
        voters.add(voter);
        return voter;*/
    }

    public static boolean isVoterExist(BigInteger id){
        boolean exist = false;
        for(int i = 0; i < voters.size(); i++){
            if(voters.get(i).getID().equals(id))
                return true;
        }
        return false;
    }

    public static String nonce() {
        SecureRandom random = new SecureRandom();
        BigInteger N = new BigInteger(32, 50, random);
        String n = N.toString();
        return n;
    }

    public static String timenow() {
        Date date = new Date();
        String time = String.valueOf(date.getTime());
        return time;
    }

    private static boolean timeIsOk(Long timestapm, long beginTime, long endTime) {
        Date date = new Date();
        long time = date.getTime();
        if(timestapm < time - beginTime){
            System.out.println("Packet dropped because of timestamp error");
            return false;
        }
        if(timestapm > time - endTime){
            System.out.println("Packet dropped because of timestamp error");
            return false;
        }
        return true;
    }


    private static boolean checkHash(byte[] m, byte[] hashed) {
        byte[] checkHash = hash(m);
        //System.out.println("checkHash: " + checkHash.length + " dec_hash: " + dec_hashed.length);
        if(checkHash.length != 16 || hashed.length != 16){
            System.out.println("Packet dropped because of hash(2) error");
            return false;
        }
        for( int i = 0; i < 16; i++){
            if(checkHash[i] != hashed[i]){
                System.out.println("Packet dropped because of hash(3) error");
                return false;
            }
        }
        return true;
    }

    private static boolean checkHash(byte[] m, byte[] hashed, PublicKey key) {
        byte[] checkHash = hash(m);
        byte[] dec_hashed = decrypt_pub_toByte(hashed, key);
        //System.out.println("checkHash: " + checkHash.length + " dec_hash: " + dec_hashed.length);
        if(checkHash.length != 16 || dec_hashed.length != 16){
            System.out.println("Packet dropped because of hash error");
            return false;
        }
        for( int i = 0; i < 16; i++){
            if(checkHash[i] != dec_hashed[i]){
                System.out.println("Packet dropped because of hash error");
                return false;
            }
        }
        return true;
    }

    private static void sendBigBytes(byte[] all, Socket socket, PublicKey key) {
        byte[] finalMSG1 = new byte[all.length / 2];
        byte[] finalMSG2 = new byte[all.length - finalMSG1.length];
        for(int i = 0; i < all.length; i++){
            if(i < finalMSG1.length){
                finalMSG1[i] = all[i];
            }
            else{
                finalMSG2[i - finalMSG1.length] = all[i];
            }

        }

        byte[] enc1 = encrypt_pub(finalMSG1, key);
        byte[] enc2 = encrypt_pub(finalMSG2, key);
        byte[] finalEnc = new byte[enc1.length + enc2.length];
        for(int i = 0; i < finalEnc.length; i++){
            if(i < enc1.length)
                finalEnc[i] = enc1[i];
            else
                finalEnc[i] = enc2[i - enc1.length];
        }
        //System.out.println(enc1.length + " "  + finalEnc.length);

        try {
            sendBytes(socket, finalEnc);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static byte[] hash(byte[] bt){
        try {
            MessageDigest ms = MessageDigest.getInstance("MD5");
            return ms.digest(bt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void sendBytes(Socket socket, byte[] myByteArray) throws IOException {
        sendBytes(socket, myByteArray, 0, myByteArray.length);
    }

    public static void sendBytes(Socket socket, byte[] myByteArray, int start, int len) throws IOException {
        if (len < 0)
            throw new IllegalArgumentException("Negative length not allowed");
        if (start < 0 || start >= myByteArray.length)
            throw new IndexOutOfBoundsException("Out of bounds: " + start);
        // Other checks if needed.

        // May be better to save the streams in the support class;
        // just like the socket variable.
        OutputStream out = socket.getOutputStream();
        DataOutputStream dos = new DataOutputStream(out);

        dos.writeInt(len);
        if (len > 0) {
            dos.write(myByteArray, start, len);
        }
    }

    public static byte[] readBytes(Socket socket) throws IOException {
        // Again, probably better to store these objects references in the support class
        InputStream in = socket.getInputStream();
        DataInputStream dis = new DataInputStream(in);

        int len = dis.readInt();
        byte[] data = new byte[len];
        if (len > 0) {
            dis.readFully(data);
        }
        return data;
    }

    public static byte[] encrypt_pub(byte[] text, PublicKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(Algorithm);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static byte[] encrypt_priv(byte[] text, PrivateKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(Algorithm);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static byte[] decrypt_priv_toByte(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(Algorithm);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return dectyptedText;
    }

    public static byte[] decrypt_pub_toByte(byte[] text, PublicKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(Algorithm);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return dectyptedText;
    }
}
