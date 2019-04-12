package com.example.demo.realization;

import com.example.demo.model.Pattern;
import com.example.demo.services.AESutil;

public class CFB extends Pattern {
    public CFB() {
        super();
    }

    public CFB(String plaintext, String key) {
        super(plaintext, key);
    }

    @Override
    public void encryption(){
        AESutil aes=new AESutil();
        try{
            ciphertexts.clear();
            t=aes.encrypt(IV.getBytes(defaultCharset),key);/*将初始向量IV进行AES加密*/
            ciphertexts.add(aes.parseByteToHex(aes.XOR(plaintexts.get(0).getBytes(defaultCharset),t)));/*将获得结果与第一组明文组进行异或运算，获得第一组密文组*/
            for (int i =1;i<plaintexts.size();i++){
                t=aes.encrypt(aes.parseHexToByte(ciphertexts.get(i-1)),key);/*将前一组密文组进行AES加密*/
                ciphertexts.add(aes.parseByteToHex(aes.XOR(plaintexts.get(i).getBytes(defaultCharset),t)));/*将获得的结果与该组明文组进行异或运算获得密文组*/
            }
            ciphertext="";
            for (int i=0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public void decryption() {
        AESutil aes=new AESutil();
        try {
            ciphertexts.clear();
            t=aes.encrypt(IV.getBytes(defaultCharset),key);/*将初始向量IV进行AES加密*/
            ciphertexts.add(new String(aes.XOR(aes.parseHexToByte(plaintexts.get(0)),t),defaultCharset));/*将获得的结果与第一组密文组进行异或运算，获得第一组明文组*/
            for (int i=1;i<plaintexts.size();i++){
                t=aes.encrypt(aes.parseHexToByte(plaintexts.get(i-1)),key);/*将前一组密文组进行AES加密*/
                ciphertexts.add(new String(aes.XOR(aes.parseHexToByte(plaintexts.get(i)),t),defaultCharset));/*与该组明文组异或后得到明文组*/

            }
            ciphertext="";
            for (int i=0;i<ciphertexts.size();i++){
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
