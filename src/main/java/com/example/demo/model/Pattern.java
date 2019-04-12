package com.example.demo.model;
import java.util.ArrayList;

public class Pattern {
    public String ciphertext;/*密文串*/
    public String plaintext;/*明文串*/
    public String key;/*密钥*/
    public String IV="oaiysa6woiua19s2";/*CFB和OFB的初始化向量IV*/
    public byte[] t;/*暂时存储处理结果的中间变量t*/
    public ArrayList<String> plaintexts=new ArrayList();/*明文组*/
    public ArrayList<String> ciphertexts=new ArrayList();/*密文组*/
    public final static String defaultCharset ="UTF-8";

    public Pattern(String plaintext, String key){
        this.plaintext=plaintext;
        this.key=key;
    }
    public Pattern(){}

    public String getCiphertext(){
        return ciphertext;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() { return key; }

    public void setPlaintext(String plaintext) {
        this.plaintext = plaintext;
    }

    public String getPlaintext() {
        return plaintext;
    }

    public String getIV() {
        return IV;
    }

    public void setIV(String IV) { this.IV = IV; }

    public void grouping(){/*字符串明文分组，每个分组固定16字节，128位*/
        int i =0;
        plaintexts.clear();
        while (true){
            if ((i+1)*16<plaintext.length()){
                plaintexts.add(plaintext.substring(i*16,i*16+16));
            }else {
                while (plaintext.length()%16!=0){
                    plaintext+=" ";/*最后不足16字节的部分用空格补全*/
                }
                plaintexts.add(plaintext.substring(i*16));
                break;
            }

            i++;
        }
    }
    public void dgrouping(){/*16进制密文分组，因为2个16进制组成一个字节所以每个分组固定32个字节*/
        int i =0;
        plaintexts.clear();
        while (true){
            if ((i+1)*32<plaintext.length()){
                plaintexts.add(plaintext.substring(i*32,i*32+32));
            }else {
                plaintexts.add(plaintext.substring(i*32));
                break;
            }
            i++;
        }
    }

    public String Rtrim(String str){/*去掉明文分组时用于补全的空格*/
        int i=str.length();
        while (str.charAt(i-1)==' '){i--;}
        return str.substring(0,i);
    }

    public void encryption(){}
    public void decryption(){}


    public String doEncryption(){
        grouping();/*明文分组*/
        encryption();/*执行加密*/
        return getCiphertext();
    }

    public String doDecryption(){
        dgrouping();/*密文分组*/
        decryption();/*执行解密*/
        ciphertext=Rtrim(ciphertext);
        return getCiphertext();
    }
}
