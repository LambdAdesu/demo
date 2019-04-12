package com.example.demo.services;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;


public class AESutil {
    private final static String defaultCharset ="UTF-8";
    private final static String KEY_AES="AES";

    public static byte[] encrypt(byte[] plaintext,String key){ /*加密方法*/
        try {
            if (key.length()!=16){
                System.out.println("密钥长度必须为16字节");
                return null;
            }
            return doAES(plaintext,key,Cipher.ENCRYPT_MODE);/*执行加密，设定为加密模式*/
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decrypt(String plaintext,String key){/*解密方法*/
        try{
            if (key.length()!=16){
                System.out.println("密钥长度必须为16字节");
                return null;
            }
            byte[] data=parseHexToByte(plaintext);/*将16进制密文转为2进制字节型*/
            return doAES(data,key,Cipher.DECRYPT_MODE);/*执行解密，设定为解密模式*/
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }

    }

    public static byte[] doAES(byte[] data,String key,int mode){/*AES加解密处理模块*/
        try {
            if (data.length==0||key.isEmpty()){return null;};
            KeyGenerator keyGenerator =KeyGenerator.getInstance(KEY_AES);/*构造密钥生成器，指定AES*/
            keyGenerator.init(128,new SecureRandom(key.getBytes()));/*根据key产生128位随机源*/
            SecretKey secretKey=keyGenerator.generateKey();/*产生原始对称密钥*/
            byte[] enCodeFormat =secretKey.getEncoded();/*原始对称密钥的字节数组*/
            Key keySpec=new SecretKeySpec(enCodeFormat,KEY_AES);/*生成AES密匙*/
            Cipher cipher=Cipher.getInstance("AES/ECB/NoPadding");/*创建密码器，设定为最基础的ECB模式，不使用补码规则*/
            cipher.init(mode,keySpec);/*根据加/解密模式进行初始化*/
            byte[] result =cipher.doFinal(data);/*进行加/解密*/
            return result;/*返回二进制结果*/
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public byte[] XOR(byte[] a,byte[] b){/*异或方法*/
        try{
            if (a.length<b.length){
                byte[] t =a;
                a=b;
                b=t;
            }
            int i=0;
            byte[] c =new byte[a.length];
            for (int j=0;j<a.length;j++){
                c[j]=(byte)(a[j]^b[i]);
                i++;
                i=(i>=b.length)?0:i;/*若a的长度大于b，则将b从第一个字节开始继续异或*/
            }
            return c;/*返回结果*/
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }



    public static byte[] parseHexToByte(String str){/*16进制字符串转2进制字节型*/
        if(str.length()<1){return null;};
        byte[] result=new byte[str.length()/2];
        for (int i=0;i<str.length()/2;i++){
            int high=Integer.parseInt(str.substring(i*2,i*2+1),16);/*前4位*/
            int low=Integer.parseInt(str.substring(i*2+1,i*2+2),16);/*后4位*/
            result[i]=(byte)(high*16+low);
        }
        return result;
    }

    public static String parseByteToHex(byte[] hex){/*2进制字节型转16进制字符串*/
        StringBuilder sb=new StringBuilder();
        for (int i=0;i<hex.length;i++){
            String hexStr =Integer.toHexString(hex[i]&0xFF);
            if(hexStr.length()==1){
                hexStr='0'+hexStr;
            }
            sb.append(hexStr.toUpperCase());
        }
        return sb.toString();
    }
}
