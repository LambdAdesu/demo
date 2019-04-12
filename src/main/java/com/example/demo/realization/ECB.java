package com.example.demo.realization;

import com.example.demo.model.Pattern;
import com.example.demo.services.AESutil;

public class ECB extends Pattern{
    public ECB(String plaintext, String key) {
        super(plaintext, key);
    }

    public ECB(){
        super();
    }

    @Override
    public void encryption(){
        AESutil aes=new AESutil();
        try {
            ciphertexts.clear();/*初始化密文串*/
            for (int i=0;i<plaintexts.size();i++){
                t=aes.encrypt(plaintexts.get(i).getBytes(defaultCharset),key);/*将分组后的明文转成2进制字节型，执行AES加密并返回加密结果*/
                ciphertexts.add(aes.parseByteToHex(t));/*将解密结果转化为16进制字符串*/
            }
            ciphertext="";
            for (int i=0;i<ciphertexts.size();i++){/*将密文组组成密文串输出*/
                ciphertext+=ciphertexts.get(i);
            }
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    @Override
    public void decryption() {
        AESutil aes = new AESutil();
        try {
            ciphertexts.clear();
            for (int i = 0; i < plaintexts.size(); i++) {
                t = aes.decrypt(plaintexts.get(i), key);/*将分组后的16进制密文进行解密*/
                ciphertexts.add(new String(t, defaultCharset));/*将解密结果的2进制转成字符串型明文*/
            }
            ciphertext = "";
            for (int i = 0; i < ciphertexts.size(); i++) {
                ciphertext += ciphertexts.get(i);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
