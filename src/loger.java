import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class loger {
    private SecretKey masterKey;
    private String filename;
    public loger(String filename) {
        this.filename = filename;
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            masterKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public void createlog(log mylog) {
        try {
            byte[] out_byte = serialize(mylog);
            Cipher ci = Cipher.getInstance("AES");
            ci.init(Cipher.ENCRYPT_MODE, masterKey);
            byte[] writable = ci.doFinal(out_byte);
            FileOutputStream fos;
            try {
                fos = new FileOutputStream(filename, true);
                System.out.println(writable.length);
                fos.write(writable);
                fos.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (NoSuchPaddingException e1) {
            e1.printStackTrace();
        } catch (IllegalBlockSizeException e1) {
            e1.printStackTrace();
        } catch (BadPaddingException e1) {
            e1.printStackTrace();
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
        }
    }

    public  ArrayList<log> getlogs(){
        FileInputStream fis;
        byte[] readbytes = null;
        try {
            fis = new FileInputStream(filename);
            fis.read(readbytes);
            fis.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Cipher ci;
        ArrayList<log> logs = new ArrayList<log>();
        try {
            ci = Cipher.getInstance("AES");
            ci.init(Cipher.DECRYPT_MODE, masterKey);
            byte[] log_bytes = ci.doFinal(readbytes);
            log mylog = (log)deserialize(log_bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return logs;


    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(obj);
        return b.toByteArray();
    }

    public static Object deserialize(byte[] bytes) throws IOException,
            ClassNotFoundException {
        ByteArrayInputStream b = new ByteArrayInputStream(bytes);
        ObjectInputStream o = new ObjectInputStream(b);
        return o.readObject();
    }
    // static ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // static ObjectOutput out = null;
    //
    // public static void main(String[] args) throws IOException {
    // }
    //
    // public static void createlog(log mylog) {
    // FileOutputStream fos;
    // try {
    // fos = new FileOutputStream("code");
    // // fos.write(mylog.getClass());
    // fos.close();
    // } catch (FileNotFoundException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // } catch (IOException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }
    //
    // }
    //
    // public static byte[] to_byte(Object o){
    // out = new ObjectOutputStream(bos);
    // out.writeObject(o);
    // byte[] out_byte = bos.toByteArray();
    // }
}