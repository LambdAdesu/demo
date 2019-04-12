package com.example.demo.realization;

import com.example.demo.model.Pattern;
import com.example.demo.services.AESutil;

public class CBC extends Pattern {
    public CBC(String plaintext, String key) {
        super(plaintext, key);
    }

    public CBC() {
        super();
    }

    @Override
    public void encryption(){
        try{
            AESutil aes=new AESutil();
            ciphertexts.clear();/*初s始化密文组*/
            t=aes.XOR(plaintexts.get(0).getBytes(defaultCharset),IV.getBytes(defaultCharset));/*将第一组明文与初始化向量IV进行异或运算*/
            ciphertexts.add(aes.parseByteToHex(aes.encrypt(t,key)));/*将结果t进行AES加密获得第一组16进制密文*/
            for (int i=1;i<plaintexts.size();i++){
                t=aes.XOR(plaintexts.get(i).getBytes(defaultCharset),aes.parseHexToByte(ciphertexts.get(i-1)));/*将明文组和上一个密文组进行异或运算*/
                ciphertexts.add(aes.parseByteToHex(aes.encrypt(t,key)));/*将获得的结果进行加密，并转为16进制字符串储存*/
            }
            ciphertext="";/*初始化密文串*/
            for (int i=0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    @Override
    public void decryption(){
        AESutil aes=new AESutil();
        try{
            ciphertexts.clear();/*初始化密文组*/
            t=aes.decrypt(plaintexts.get(0),key);/*将第一组密文用key进行解密*/
            ciphertexts.add(new String(aes.XOR(t,IV.getBytes(defaultCharset)),defaultCharset));/*将解密后的结果与初始向量IV进行异或，得到第一组明文组*/
            for (int i=1;i<plaintexts.size();i++){
                t=aes.decrypt(plaintexts.get(i),key);/*将密文组进行解密*/
                ciphertexts.add(new String(aes.XOR(t,aes.parseHexToByte(plaintexts.get(i-1))),defaultCharset));/*将获得的结果与上一个密文组进行异或运算获得明文组*/
            }
            ciphertext="";/*初始化明文串*/
            for (int i=0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }

}