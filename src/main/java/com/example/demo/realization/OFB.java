package com.example.demo.realization;

import com.example.demo.model.Pattern;
import com.example.demo.services.AESutil;

public class OFB extends Pattern {
    public OFB() {
        super();
    }

    public OFB(String plaintext, String key) {
        super(plaintext, key);
    }

    @Override
    public void encryption() {
        AESutil aes=new AESutil();
        try{
            ciphertexts.clear();
            t=aes.encrypt(IV.getBytes(defaultCharset),key);/*将初始向量IV进行AES加密*/
            ciphertexts.add(aes.parseByteToHex(aes.XOR(plaintexts.get(0).getBytes(defaultCharset),t)));/*将获得的结果与第一组明文组进行异或获得第一组密文组*/
            for (int i =1;i<plaintexts.size();i++){
                t=aes.encrypt(t,key);/*将上一组的加密结果作为新的向量进行加密*/
                ciphertexts.add(aes.parseByteToHex(aes.XOR(plaintexts.get(i).getBytes(defaultCharset),t)));/*与本组明文组异或后获得本组密文组*/
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
            t=aes.encrypt(IV.getBytes(defaultCharset),key);/*将初始向量IV进行AES加密*/
            ciphertexts.add(new String(aes.XOR(aes.parseHexToByte(plaintexts.get(0)),t),defaultCharset));/*将获得的结果与第一组明文组进行异或运算获得第一组明文组*/
            for (int i =1;i<plaintexts.size();i++){
                t=aes.encrypt(t,key);/*将上一组的加密结果作为新的向量进行加密*/
                ciphertexts.add(new String(aes.XOR(aes.parseHexToByte(plaintexts.get(i)),t),defaultCharset));/*与本组密文组异或后获得本组明文组*/
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

