package main;

import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@RestController
public class UserController {

    List<User> list = new ArrayList<>();
    List<String> log = new ArrayList<>();

    public UserController() {
        list.add(new User("Roman", "Simko", "roman", "heslo"));
    }

    @RequestMapping("/time")
    public ResponseEntity<String> getTime(@RequestParam(value = "token") String token) {
        JSONObject res = new JSONObject();
        if (token == null) {
            res.put("error", "Bad request");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (checkToken(token)) {


            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
            LocalDateTime localTime = LocalDateTime.now();
            String time = dtf.format(localTime);
            res.put("current time", time);
            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }
        res.put("error", "Invalid token");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }


    @RequestMapping(method = RequestMethod.POST, value = "/login")
    public ResponseEntity<String> login(@RequestBody String credential) {
        JSONObject obj = new JSONObject(credential);
        if (obj.has("login") && obj.has("password")) {
            JSONObject res = new JSONObject();
            if (obj.getString("password").isEmpty() || obj.getString("login").isEmpty()) {
                res.put("error", "Password and login are mandatory fields");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }
            if (findLogin(obj.getString("login")) && checkPassword(obj.getString("login"), obj.getString("password"))) {
                User loggedUser = getUser(obj.getString("login"));
                if (loggedUser == null) {

                    return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{}");
                }
                res.put("fname", loggedUser.getFname());
                res.put("lname", loggedUser.getLname());
                res.put("login", loggedUser.getLogin());
                String token = generateToken();
                res.put("token", token);
                loggedUser.setToken(token);
                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            } else {
                res.put("error", "Invalid login or password");
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

        } else {
            JSONObject res = new JSONObject();
            res.put("error", "Invalid body request");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

    }

    @RequestMapping(method = RequestMethod.POST, value = "/signup")
    public ResponseEntity<String> signup(@RequestBody String data) {

        JSONObject jsonObject = new JSONObject(data);

        if (jsonObject.has("fname") && jsonObject.has("lname") && jsonObject.has("login")
                && jsonObject.has("password")) {
            if (findLogin(jsonObject.getString("login"))) {
                JSONObject res = new JSONObject();
                res.put("error", "user already exists");
                return ResponseEntity.status(400).body(res.toString());
            }
            String password = jsonObject.getString("password");
            if (password.isEmpty()) {
                JSONObject res = new JSONObject();
                res.put("error", "password is a mandatory field");
                return ResponseEntity.status(400).body(res.toString());
            }
            String hashpas = hashPassword(password);

            User user = new User(jsonObject.getString("fname"), jsonObject.getString("lname"),
                    jsonObject.getString("login"), hashpas);
            list.add(user);
            JSONObject res = new JSONObject();
            res.put("fname", jsonObject.getString("fname"));
            res.put("lname", jsonObject.getString("lname"));
            res.put("login", jsonObject.getString("login"));
            return ResponseEntity.status(200).body(res.toString());
        } else {
            JSONObject res = new JSONObject();
            res.put("error", "invalid input");
            return ResponseEntity.status(400).body(res.toString());
        }

    }

    private String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));


    }


    @RequestMapping(method = RequestMethod.POST, value = "/logout")
    public ResponseEntity<String> logout(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(data);

        String login = obj.getString("login");
        User user = getUser(login);
        if (user != null && checkToken(token)) {

            user.setToken(null);
            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body("{}");
        }
        JSONObject res = new JSONObject();
        res.put("error", "Incorrect login or token");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }


    @RequestMapping(method = RequestMethod.POST, value = "/changePassword")
    public ResponseEntity<String> changePassword(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {

        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = getUser(obj.getString("login"));


        if (temp == null) {
            res.put("error", "Incorrect login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (obj.has("login") && obj.has("oldpassword") && obj.has("newpassword")) {


            System.out.println(obj.getString("oldpassword"));
            if (temp.getLogin().equals(obj.getString("login")) && BCrypt.checkpw(obj.getString("oldpassword"), temp.getPassword())
                    && temp.getToken().equals(token)) {
                temp.setPassword(obj.getString("newpassword"));
            } else {
                res.put("error", "Wrong password or token");
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

        } else
            res.put("error", "Wrong input");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }

    @RequestMapping(value = "/log")
    public ResponseEntity<String> log(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {

        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = getUser(obj.getString("login"));

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("ddMMyy HH:mm:ss");
        LocalDateTime localTime = LocalDateTime.now();
        String time = dtf.format(localTime);

        if (temp == null) {
            res.put("error", "Incorrect login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }


        if (obj.has("login")) {
            if (temp.getLogin().equals(obj.getString("login")) && temp.getToken().equals(token)) {
                res.put("type", "login");
                res.put("login", temp.getLogin());
                res.put("datetime", time);
                log.add(res.toString());

            } else {
                res.put("error", "Wrong login or token");
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }
        } else
            res.put("error", "Wrong input");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }


    private boolean findLogin(String login) {
        for (User user : list) {
            if (user.getLogin().equalsIgnoreCase(login))
                return true;
        }
        return false;
    }


    private boolean checkPassword(String login, String password) {
        User user = getUser(login);
        if (user != null) {

            return BCrypt.checkpw(password, user.getPassword());
        }
        return false;
    }

    private User getUser(String login) {
        for (User user : list) {
            if (user.getLogin().equals(login))
                return user;
        }
        return null;
    }

    private boolean checkToken(String token) {
        for (User user : list) {
            if (user.getToken().equals(token) && user.getToken() != null) {
                return true;
            }
        }
        return false;
    }


    private String generateToken() {
        return Long.toString(Math.abs(new SecureRandom().nextLong()), 16);

    }
}
