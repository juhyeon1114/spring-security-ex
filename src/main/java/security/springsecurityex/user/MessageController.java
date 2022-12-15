package security.springsecurityex.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MessageController {

    @GetMapping
    public String mypage() {
        return "user/messages";
    }

}
