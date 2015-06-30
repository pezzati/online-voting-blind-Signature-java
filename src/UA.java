import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

public class UA {

    public static final String Algorithm = "RSA";
    public static PublicKey publicAS;
    public static PrivateKey privateAS;
    public static PublicKey publicVS;
    public static PrivateKey privateVS;
    public static PublicKey publicUA;
    public static PrivateKey privateUA;

    public static BigInteger module;
    public static BigInteger publicExponent;
    public static BigInteger R;

    public static Socket socket;

    static Random rand;
    static BigInteger IDua;
    static String Nua;

    public static SecretKey key_as;

    public static final long beginTime = 3000;
    public static final long EndTime = 0;

    public static String N_as;
    public static String N_asvs;
    public static String finalVote;


    public static void main(String[] args) {


        //Connecting to AS
        try {
            socket = new Socket("localhost", 8081);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateUA= keyPair.getPrivate();
            publicUA = keyPair.getPublic();

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            outputStream.writeObject(publicUA);
            System.out.println("Public key sent to AS");

            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            publicAS = (PublicKey) objectInputStream.readObject();
            System.out.println("Public key of AS received");




            initialize();

            /**
             * first message: PUas
             * M = IDua + Nua + Time
             * sign = sign(M)
             */

            String firstM = IDua.toString() + " " + Nua + " " + timenow();
            byte[] hash_firstM = hash(firstM.getBytes());
            byte[] signature = encrypt_priv(hash_firstM, privateUA);
            byte[] firstMessage = new byte[firstM.getBytes().length
                    + signature.length];
            System.arraycopy(firstM.getBytes(), 0, firstMessage, 0,
                    firstM.getBytes().length);
            System.arraycopy(signature, 0, firstMessage, firstM.getBytes().length,
                    signature.length);
            // first message is ready. must be encrypted with PUas and sent to AS.
            //byte[] first_to_send = encrypt_pub(firstMessage, publicAS);
            sendBigBytes(firstMessage, socket, publicAS);

            System.out.println("First sent");

            while(true){
                //first reply received.
                byte[] firstReply = readBytes(socket);
                System.out.println("first reply rec");
                byte[] msg1 = new byte[128];
                byte[] msg2 = new byte[128];
                for(int i=0; i<128; i++)
                    msg1[i] = firstReply[i];
                for(int i=0; i<128; i++)
                    msg2[i] = firstReply[i + 128];
                byte[] dec_msg1 = decrypt_priv(msg1, privateUA);
                byte[] dec_msg2 = decrypt_priv(msg2, privateUA);

                byte[] all_dec = new byte[dec_msg1.length + dec_msg2.length];

                for(int i=0; i<all_dec.length; i++){
                    if(i < dec_msg1.length)
                        all_dec[i] = dec_msg1[i];
                    else
                        all_dec[i] = dec_msg2[i - dec_msg1.length];
                }

                byte[] m_byte = new byte[all_dec.length - 128];
                byte[] hashed_geted = new byte[128];

                for(int i=0; i<all_dec.length; i++){
                    if(i< m_byte.length)
                        m_byte[i] = all_dec[i];
                    else
                        hashed_geted[i - m_byte.length] = all_dec[i];
                }

                if(!checkHash(m_byte, hashed_geted, publicAS))
                    continue;






                byte[] bt = new byte[32];
                for(int i = 0; i < 32; i++)
                    bt[i] = m_byte[i];
                byte[] content = new byte[m_byte.length - 32];
                for(int i = 0; i < m_byte.length - 32; i++)
                    content[i] = m_byte[i + 32];

                String M = new String(content);
                //System.out.println(M);
                if(!timeIsOk(Long.valueOf(M.split("[ ]")[2]), beginTime, EndTime))
                    continue;

                if(!(M.split("[ ]")[0].equals(Nua))){
                    System.out.println("Packet dropped because of N_as error");
                    continue;
                }

                N_as = M.split("[ ]")[1];

                //Key session between AS-UA is set now
                key_as = new SecretKeySpec(bt, "AES");


                break;
            }
//            byte[] firstReply_decrepted = decrypt_priv(firstReply, privateUA);

            /**
             * second message: Ks
             * M = IDua + Nas + Time + m'
             * Hash(M)
             */
            Scanner in = new Scanner(System.in);
            System.out.println("Please Enter Your Vote:");
            String vote = in.nextLine();
            System.out.println("Thank You For Voting.");
            String blinded_vote = blind(vote);
            // Nas had been received from AS in last received message

            String secondM = IDua.toString() + " " + N_as + " " + timenow() + " " + blinded_vote;
            byte[] hash_secondM = hash(secondM.getBytes());
            byte[] secondMessage = new byte[secondM.getBytes().length + hash_secondM.length];
            System.arraycopy(secondM.getBytes(), 0, secondMessage, 0, secondM.getBytes().length);
            System.arraycopy(hash_secondM, 0, secondMessage, secondM.getBytes().length, hash_secondM.length);
            //second message is ready. must be encrypted with Ks and sent to AS to sign it.
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key_as);
            byte[] secondMessageToSend = cipher.doFinal(secondMessage);
            sendBytes(socket, secondMessageToSend);


            while(true){
                byte[] undecSignedVoteWithHash = readBytes(socket);
                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key_as);
                byte[] SignedVoteWithHash = cipher.doFinal(undecSignedVoteWithHash);
                byte[] SignedVote = new byte[SignedVoteWithHash.length - 16];
                byte[] hashOfSignedVote = new byte[16];
                System.arraycopy(SignedVoteWithHash, 0, SignedVote, 0, SignedVoteWithHash.length - 16);
                System.arraycopy(SignedVoteWithHash, SignedVoteWithHash.length - 16, hashOfSignedVote, 0, 16);

                if(!checkHash(SignedVote, hashOfSignedVote))
                    continue;
                String SignedVote_str = new String(SignedVote);

                N_asvs = SignedVote_str.split("[ ]")[1];
                if(Integer.valueOf(SignedVote_str.split("[ ]")[2]) != (key_as.hashCode() + 1))
                    continue;
                if(!timeIsOk(Long.valueOf(SignedVote_str.split("[ ]")[3]), beginTime, EndTime))
                    continue;

                finalVote = unblind(SignedVote_str.split("[ ]")[0]);


                break;
            }



            Socket vs_socket = new Socket("localhost", 8082);

            ObjectOutputStream vs_outputStream = new ObjectOutputStream(vs_socket.getOutputStream());
            vs_outputStream.writeObject(publicUA);
            System.out.println("Public key sent to VS");

            ObjectInputStream vs_objectInputStream = new ObjectInputStream(vs_socket.getInputStream());
            publicVS = (PublicKey) vs_objectInputStream.readObject();
            System.out.println("Public key of VS received");


            /**
             * third message: PUvs
             * M = S + Nas,vs + Time
             * Hash(M)
             */
            // mock nonce.
            String Nasvs = N_asvs;
            // mock signed vote.
//            byte[] signed_vote = unblind(null);
            String thirdM = finalVote + " " + Nasvs + " " + timenow();
            byte[] hash_thirdM = hash(thirdM.getBytes());
            byte[] thirdMessage = new byte[thirdM.getBytes().length + hash_thirdM.length];
            System.arraycopy(thirdM.getBytes(), 0, thirdMessage, 0, thirdM.getBytes().length);
            System.arraycopy(hash_thirdM, 0, thirdMessage, thirdM.getBytes().length, hash_thirdM.length);
            //third message is ready. must be encrypted with PUvs and sent to VS.
            sendVeryBigPacket(thirdMessage, vs_socket, publicVS);

            while (true){
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

                if(Integer.valueOf(reportbackStr.split("[ ]")[1]) != (key_as.hashCode() + 3))
                    continue;

                if(!timeIsOk(Long.valueOf(reportbackStr.split("[ ]")[2]), beginTime, EndTime))
                    continue;
                String r = reportbackStr.split("[ ]")[0];
                if(r.equals("1"))
                    System.out.println("Your vote is added");
                else
                    System.out.println("Your vote is not added");
                break;
            }


        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
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

    private static void sendVeryBigPacket(byte[] thirdMessage, Socket vs_socket, PublicKey publicKey) {
        byte[][] finalMsgs = new byte[6][];
        for(int i = 0; i < 5; i++){
            finalMsgs[i] = new byte[117];
            for(int j = 0; j < 117; j++)
                finalMsgs[i][j] = thirdMessage[i * 117 + j];
        }
        finalMsgs[5] = new byte[thirdMessage.length % 117];
        System.arraycopy(thirdMessage, 5 * 117, finalMsgs[5], 0, thirdMessage.length % 117);

        byte[] encMsg = new byte[768];
        for(int i = 0; i < 6; i++){
            byte[] ecnTemp = encrypt_pub(finalMsgs[i], publicVS);
            System.arraycopy(ecnTemp, 0, encMsg, i * 128, 128);
        }
        try {
            sendBytes(vs_socket, encMsg);
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    private static boolean checkHash(byte[] m, byte[] hashed, PublicKey key) {
        byte[] checkHash = hash(m);
        byte[] dec_hashed = decrypt_pub(hashed, key);
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

    public static void initialize() {
        rand = new Random();
        IDua = new BigInteger("8888");
        System.out.println(IDua.toString().length());
        Nua = nonce();

        module = ((RSAPublicKey) publicAS).getModulus();
        publicExponent = ((RSAPublicKey) publicAS).getPublicExponent();

        BigInteger gcd;
        do {
            R = new BigInteger(1024, 0, rand);
            gcd = module.gcd(R);
        } while (BigInteger.valueOf(1).compareTo(gcd) < 0);
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

    //	public static byte[] signVote(byte[] message){
//		byte[] blinded_message = blind(message);
//		//send blinded message to AS and get the blinded signed message from AS.
//		byte[] blinded_signed_message = null;
//		byte[] unblinded_signed_message = unblind(blinded_signed_message);
//		return unblinded_signed_message;
//	}
    // returns blinded message in byte array
    public static String blind(String message) {
        BigInteger blinder = R.modPow(publicExponent, module);
        BigInteger message_in_biginteger = new BigInteger(message);
        BigInteger blinded_message = message_in_biginteger.multiply(blinder);
        return blinded_message.toString();
    }

    public static String unblind(String message) {
        BigInteger blinded_signed_message = new BigInteger(message);
        BigInteger unblinded_signed_message = blinded_signed_message.multiply(R
                .modInverse(module));
        return unblinded_signed_message.toString();
    }

    public static byte[] encrypt(byte[] text, SecretKey key) {
        byte[] result = null;
        return result;
    }

    public static byte[] decrypt(byte[] text, SecretKey key) {
        byte[] result = null;
        return result;
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

    public static byte[] hash(byte[] bt) {
        try {
            MessageDigest ms = MessageDigest.getInstance("MD5");
            return ms.digest(bt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
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

    /*public static String decrypt_priv_to_string(byte[] text, PrivateKey key) {
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

        return new String(dectyptedText);
    }*/

    public static byte[] decrypt_priv(byte[] text, PrivateKey key) {
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

    public static byte[] decrypt_pub(byte[] text, PublicKey key) {
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

}