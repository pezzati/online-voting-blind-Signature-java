
import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;

public class VS {
    public static final String Algorithm = "RSA";
    public static final long beginTime = 3000;
    public static final long EndTime = 0;
    public static SecretKey key_as;
    public static ArrayList<String> Nonces;
    public static int ks;
    public static loger loger;

    public static void main(String[] args) {
        loger = new loger("VSLog");
        Nonces = new ArrayList<String>();
        BigInteger N_vs;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm);
            //SecureRandom secureRandom = SecureRandom.getInstance(Algorithm);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey priv = keyPair.getPrivate();
            PublicKey pub = keyPair.getPublic();



            ServerSocket serverSocket = new ServerSocket(8080);
            Socket socket = serverSocket.accept();

            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            PublicKey pub_as = (PublicKey) objectInputStream.readObject();
            System.out.println("Public key of AS received");

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            outputStream.writeObject(pub);
            System.out.println("Public key sent to AS");

            while (true){
                //Get first msg of key session set from AS
                byte[] msg = readBytes(socket);
                byte[] msg1 = new byte[128];
                byte[] msg2 = new byte[128];
                for(int i = 0; i < 128; i++)
                    msg1[i] = msg[i];
                for(int i = 0; i < 128; i++)
                    msg2[i] = msg[i + 128];

                byte[] dec_msg1 = decrypt_priv_toByte(msg1, priv);
                byte[] dec_msg2 = decrypt_priv_toByte(msg2, priv);
                byte[] all_dec = new byte[152];

                for (int i = 0; i < 152; i++){
                    if(i < dec_msg1.length)
                        all_dec[i] = dec_msg1[i];
                    else
                        all_dec[i] = dec_msg2[i - dec_msg1.length];
                }

                byte[] m_byte = new byte[24];
                byte[] hashed = new byte[128];

                for(int i = 0; i < 152; i++){
                    if (i < 24)
                        m_byte[i] = all_dec[i];
                    else
                        hashed[i - 24] = all_dec[i];
                }

                String m = new String(m_byte);

                if(!timeIsOk(Long.valueOf(m.split("[ ]")[1]), beginTime, EndTime))
                    continue;
                if(!checkHash(m_byte, hashed, pub_as))
                    continue;

                createLog(new log(m_byte, "AS", "VS"));


                //Set session key
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
                key_as = keyGenerator.generateKey();
                ks = key_as.hashCode();
                byte[] bt = key_as.getEncoded();

                SecureRandom random = new SecureRandom();
                BigInteger N_as = new BigInteger(m.split("[ ]")[0]);
                N_vs = new BigInteger(32, 50, random);
                Date date = new Date();
                String time = String.valueOf(date.getTime());

                String msg_m = N_as.toString() + " " + N_vs.toString() + " " + time;
                //System.out.println(msg_m);
                //System.out.println("bt.getEncoded: " + bt.length + " msg_m: " + msg_m.getBytes().length);

                byte[] msg_m_B = new byte[bt.length + msg_m.getBytes().length];
                for(int i = 0; i < msg_m_B.length; i++){
                    if(i < bt.length)
                        msg_m_B[i] = bt[i];
                    else
                        msg_m_B[i] = msg_m.getBytes()[i - bt.length];
                }
                //System.out.println("M.size: " + msg_m_B.length);

                createLog(new log(msg_m_B, "VS", "AS"));

                byte[] send_hashed = encrypt_priv(hash(msg_m_B), priv);

                byte[] send_m_b = new byte[msg_m_B.length + send_hashed.length];
                for(int i = 0; i < send_m_b.length; i++){
                    if(i < msg_m_B.length)
                        send_m_b[i] = msg_m_B[i];
                    else
                        send_m_b[i] = send_hashed[i - msg_m_B.length];
                }

                sendBigBytes(send_m_b, socket, pub_as);
                break;
            }

            while (true){
                byte[] msg = readBytes(socket);
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key_as);

                byte[] dec_msg = cipher.doFinal(msg);
                byte[] dec_m = new byte[24];
                byte[] dec_hash = new byte[16];
                for(int i = 0; i < 40; i++){
                    if(i < 24)
                        dec_m[i] = dec_msg[i];
                    else
                        dec_hash[i - 24] = dec_msg[i];
                }
                String M = new String(dec_m);
                //System.out.println(M);

                if(!timeIsOk(Long.valueOf(M.split("[ ]")[1]), beginTime, EndTime))
                    continue;
                if(!checkHash(dec_m, dec_hash))
                    continue;

                createLog(new log(dec_m, "AS", "VS"));

                BigInteger N_vs_back = new BigInteger(M.split("[ ]")[0]);
                if(!N_vs_back.equals(N_vs)){
                    System.out.println("Packet dropped because of N_vs error");
                    continue;
                }


                break;
            }

            ServerSocket server_ua = new ServerSocket(8082);
            while (true){

                Socket ua_socket = server_ua.accept();

                ObjectInputStream ua_objectInputStream = new ObjectInputStream(ua_socket.getInputStream());
                PublicKey pub_ua = (PublicKey) ua_objectInputStream.readObject();
                System.out.println("Public key of UA received");

                ObjectOutputStream ua_outputStream = new ObjectOutputStream(ua_socket.getOutputStream());
                ua_outputStream.writeObject(pub);
                System.out.println("Public key sent to UA");

                byte[] encBlindedVoteWithHash = readBytes(ua_socket);
                byte[] BlindedVoteWithHash = decBigBytes(encBlindedVoteWithHash, priv);

                byte[] hashOfBlindedVote = new byte[16];
                System.arraycopy(BlindedVoteWithHash, BlindedVoteWithHash.length - 16, hashOfBlindedVote, 0 , 16);

                byte[] BlindedVote = new byte[BlindedVoteWithHash.length - 16];
                System.arraycopy(BlindedVoteWithHash, 0, BlindedVote, 0, BlindedVoteWithHash.length - 16);

                if(!checkHash(BlindedVote, hashOfBlindedVote))
                    continue;
                String BlindedVote_str = new String(BlindedVote);
                if(!timeIsOk(Long.valueOf(BlindedVote_str.split("[ ]")[2]), beginTime, EndTime))
                    continue;

                log log = new log(BlindedVote, "UA", "VS");
                log.setUa_pub_key(pub_ua);
                createLog(log);

                String Nasvs = BlindedVote_str.split("[ ]")[1];
                if(Nonces.contains(Nasvs))
                    continue;

                Nonces.add(Nasvs);

                String blindedVote = BlindedVote_str.split("[ ]")[0];
                BigInteger modulus = ((RSAPublicKey)pub_as).getModulus();
                BigInteger public_exponent = ((RSAPublicKey)pub_as).getPublicExponent();
                BigInteger blindedvote_int = new BigInteger(blindedVote);
                BigInteger vote = blindedvote_int.modPow(public_exponent, modulus);
                System.out.println("vote = " + vote.toString());

                int result;
                if(!(vote.intValue() >= 1 && vote.intValue() <= 20))
                    result = 0;
                else
                    result = 1;

                ks++;
                String report = result + " " + Nasvs + " " + ks + " " + timenow();
                byte[] hash_report = hash(report.getBytes());
                byte[] rep_tosend = new byte[report.getBytes().length + hash_report.length];
                System.arraycopy(report.getBytes(), 0, rep_tosend, 0, report.getBytes().length);
                System.arraycopy(hash_report, 0, rep_tosend, report.getBytes().length, hash_report.length);

                createLog(new log(report.getBytes(), "VS", "AS"));

                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key_as);
                byte[] tosend = cipher.doFinal(rep_tosend);

                sendBytes(socket, tosend);

                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key_as);
                byte[] reportWithHash = cipher.doFinal(readBytes(socket));

                byte[] reportBack = new byte[reportWithHash.length - 16];
                byte[] hashReport = new byte[16];
                for(int i = 0; i < reportWithHash.length; i++){
                    if(i < reportBack.length)
                        reportBack[i] = reportWithHash[i];
                    else
                        hashReport[i - reportBack.length] = reportWithHash[i];
                }


                if(!checkHash(reportBack, hashReport))
                    continue;
                String reportbackStr = new String(reportBack);
                if(Integer.valueOf(reportbackStr.split("[ ]")[1]) != (ks + 1))
                    continue;
                ks++;

                if(!timeIsOk(Long.valueOf(reportbackStr.split("[ ]")[2]), beginTime, EndTime))
                    continue;

                createLog(new log(reportBack, "AS", "VS"));

            }


        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
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



    public static String timenow() {
        Date date = new Date();
        String time = String.valueOf(date.getTime());
        return time;
    }

    private static byte[] decBigBytes(byte[] thirdMessage, PrivateKey key) {
        byte[][] decMsgs = new byte[6][];
        int size = 0;
        for(int i = 0; i < 6; i++){
            byte[] ecnTemp = new byte[128];
            System.arraycopy(thirdMessage, i * 128, ecnTemp, 0, 128);
            decMsgs[i] = decrypt_priv_toByte(ecnTemp, key);
            size = size + decMsgs[i].length;
        }
        byte[] res = new byte[size];
        for(int i = 0; i < 5; i++){
            System.arraycopy(decMsgs[i], 0, res, i * 117, 117);
        }
        System.arraycopy(decMsgs[5], 0, res, 5 * 117, size % 117);
        return res;
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

    public static byte[] hash(byte[] bt){
        try {
            MessageDigest ms = MessageDigest.getInstance("MD5");
            return ms.digest(bt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
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

    private static boolean checkHash(byte[] m, byte[] hashed) {
        byte[] checkHash = hash(m);
        //System.out.println("checkHash: " + checkHash.length + " dec_hash: " + dec_hashed.length);
        if(checkHash.length != 16 || hashed.length != 16){
            System.out.println("Packet dropped because of hash(2) error");
            return false;
        }
        for( int i = 0; i < 16; i++){
            if(checkHash[i] != hashed[i]){
                System.out.println("Packet dropped because of hash(2) error");
                return false;
            }
        }
        return true;
    }


    private static void createLog(log log) {
        loger.createlog(log);
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
