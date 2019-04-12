package com.example.demo.realization;

import com.example.demo.model.Pattern;
import com.example.demo.services.AESutil;

public class CTR extends Pattern{
    private String nonce="A5C77628BAE97A12";/*计数器的Nonce部分，长度为16字节的16进制字符串*/
    public CTR() {
        super();
    }

    public CTR(String plaintext, String key) {
        super(plaintext, key);
    }

    @Override
    public void encryption() {
        AESutil aes=new AESutil();
        try{
            ciphertexts.clear();
            for (int i =0;i<plaintexts.size();i++){
                String counter=Integer.toHexString(i);/*计数器的自增算子部分*/
                while (counter.length()<16){/*将自增算子的长度用0补成16字节*/
                    counter="0"+counter;
                }
                String hexCounter=nonce +counter;/*获得完整的计数器*/
                t=aes.encrypt(aes.parseHexToByte(hexCounter),key);/*将计数器进行AES加密*/
                ciphertexts.add(aes.parseByteToHex(aes.XOR(plaintexts.get(i).getBytes(defaultCharset),t)));/*将加密结果与明文组进行异或获得密文组*/
            }
            ciphertext="";
            for (int i =0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    @Override
    public void decryption() {
        AESutil aes=new AESutil();
        try{
            ciphertexts.clear();
            for (int i =0;i<plaintexts.size();i++){
                String counter=Integer.toHexString(i);/*计数器的自增算子*/
                while (counter.length()<16){
                    counter="0"+counter;
                }
                String hexCounter=nonce +counter;/*获得完整的计数器*/
                t=aes.encrypt(aes.parseHexToByte(hexCounter),key);/*将计数器进行AES加密*/
                ciphertexts.add(new String(aes.XOR(aes.parseHexToByte(plaintexts.get(i)),t)));/*将加密结果与密文组进行异或获得明文组*/
            }
            ciphertext="";
            for (int i =0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
