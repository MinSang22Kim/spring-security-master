package io.security.spring_security_master;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "LoginPage";
    }

    @GetMapping("logoutSuccess")
    public String logoutSuccess() {
        return "logoutSuccess";
    }
}
