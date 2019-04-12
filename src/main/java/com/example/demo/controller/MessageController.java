package com.example.demo.controller;//package com.ngnb.controller;


import com.example.demo.realization.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/jsp")
public class MessageController {
    @RequestMapping(value = "/",method= RequestMethod.POST)
    public String end(HttpServletRequest request, Model model){
        try {
            String plaintext=request.getParameter("plaintext");
            String keyword=request.getParameter("keyword");
            int type=Integer.parseInt(request.getParameter("type"));
            int mode=Integer.parseInt(request.getParameter("mode"));
            String ciphertext="";
            switch (type) {
                case 0:
                    ECB ecb = new ECB(plaintext, keyword);
                    if (mode == 0) {
                        ecb.doEncryption();
                    } else {
                        ecb.doDecryption();
                    }
                    ciphertext=ecb.getCiphertext();
                    break;
                case 1:
                    CBC cbc = new CBC(plaintext, keyword);
                    if (mode == 0) {
                        cbc.doEncryption();
                    } else {
                        cbc.doDecryption();
                    }
                    ciphertext=cbc.getCiphertext();
                    break;
                case 2:
                    CFB cfb = new CFB(plaintext, keyword);
                    if (mode == 0) {
                        cfb.doEncryption();
                    } else {
                        cfb.doDecryption();
                    }
                    ciphertext=cfb.getCiphertext();
                    break;
                case 3:
                    OFB ofb = new OFB(plaintext, keyword);
                    if (mode == 0) {
                        ofb.doEncryption();
                    } else {
                        ofb.doDecryption();
                    }
                    ciphertext=ofb.getCiphertext();
                    break;
                case 4:
                    CTR ctr = new CTR(plaintext, keyword);
                    if (mode == 0) {
                        ctr.doEncryption();
                    } else {
                        ctr.doDecryption();
                    }
                    ciphertext=ctr.getCiphertext();
                    break;
            }
            request.setAttribute("ciphertext",ciphertext);
            return "jsp/end";
        }catch (Exception e){
            request.setAttribute("ciphertext","错误");
            return "jsp/end" ;
        }

    }
}
