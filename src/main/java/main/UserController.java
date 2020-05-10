package main;

import org.json.JSONArray;
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
    Database db = new Database();

    List<User> list = new ArrayList<>();
    List<String> log = new ArrayList<>();
    List<String> messages = new ArrayList<>();

    public UserController() {
        db.getConnection();
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
        JSONObject res = new JSONObject();
        if (obj.has("login") && obj.has("password")) {

            if (obj.getString("password").isEmpty() || obj.getString("login").isEmpty()) {
                res.put("error", "Password and login are mandatory fields");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }
            User loggedUser = db.getUser(obj.getString("login"));

            if (!db.findLogin(obj.getString("login")) && db.checkPassword(obj.getString("login"),
                    obj.getString("password"))) {

                db.loginUser(obj.getString("login"), obj.getString("password"));
                res.put("fname", loggedUser.getFname());
                res.put("lname", loggedUser.getLname());
                res.put("login", loggedUser.getLogin());
                res.put("token", db.getToken(loggedUser.getLogin()));


//                writeLog("login", obj.getString("login"));
                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            } else {
                res.put("error", "Wrong login or password");
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

        }
        res.put("error", "Missing login or password");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }

    @RequestMapping(method = RequestMethod.POST, value = "/signup")
    public ResponseEntity<String> signup(@RequestBody String data) {

        JSONObject jsonObject = new JSONObject(data);
        JSONObject res = new JSONObject();
        if (jsonObject.has("fname") && jsonObject.has("lname") && jsonObject.has("login")
                && jsonObject.has("password")) {

            String password = jsonObject.getString("password");
            if (password.isEmpty()) {

                res.put("error", "password is a mandatory field");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

            if (db.findLogin(jsonObject.getString("login"))) {
                db.addUser(jsonObject.getString("fname"), jsonObject.getString("lname"),
                        jsonObject.getString("login"), jsonObject.getString("password"));

                res.put("fname", jsonObject.getString("fname"));
                res.put("lname", jsonObject.getString("lname"));
                res.put("login", jsonObject.getString("login"));

                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            } else {

                res.put("error", "Login already exists");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }
        }
        res.put("error", "Something is missing");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }



    @RequestMapping(method = RequestMethod.POST, value = "/logout")
    public ResponseEntity<String> logout(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(data);

        String login = obj.getString("login");
        User user = db.getUser(login);
        if (user != null && db.checkToken(token)) {

            user.setToken(null);
            db.logoutUser(obj.getString("login"), token);
//            writeLog("logout", user.getLogin());
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
        User temp = db.getUser(obj.getString("login"));


        if (temp == null) {
            res.put("error", "Incorrect login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }


        if (obj.has("login") && obj.has("newPassword") && obj.has("oldPassword")) {


            if (!db.findLogin(temp.getLogin()) && BCrypt.checkpw(obj.getString("oldPassword"), temp.getPassword())
                    && db.checkToken(token)) {

                db.changePassword(temp.getPassword(), obj.getString("newPassword"),
                        obj.getString("login"), token);

                temp.setPassword(obj.getString("newPassword"));
                return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(res.toString());

            } else {
                res.put("error", "Wrong password or token");
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

        } else
            res.put("error", "Wrong input");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }

    @RequestMapping(value = "/log")
    public ResponseEntity<String> log(@RequestBody String data, @RequestHeader(name = "Authorization") String token, @RequestParam(required = false) String type) {

        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = getUser(obj.getString("login"));

        if (temp == null) {
            res.put("error", "Incorrect login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (obj.has("login")) {
            JSONArray arr = new JSONArray();
            for (String record : log) {
                if (temp.getLogin().equals(obj.getString("login")) && temp.getToken().equals(token)) {
                    if (type == null) {
                        JSONObject temps = new JSONObject(record);
                        arr.put(temps);
                    } else if (type.equals("login")) {
                        JSONObject temps = new JSONObject(record);
                        if (temps.getString("type").equals("login")) {
                            arr.put(temps);
                        }
                    } else if (type.equals("logout")) {
                        JSONObject temps = new JSONObject(record);
                        if (temps.getString("type").equals("logout")) {
                            arr.put(temps);
                        }
                    }

                }
            }

            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(arr.toString());
        }


        res.put("error", "Wrong login or token");
        return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }

    private void writeLog(String type, String login) {
        JSONObject obj = new JSONObject();
        obj.put("type", type);
        obj.put("login", login);
        obj.put("datetime", getTime());
        log.add(obj.toString());
    }

    @RequestMapping(method = RequestMethod.POST, value = "/message/new")
    public ResponseEntity<String> sendMessage(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = getUser(obj.getString("from"));

        if (temp == null) {
            res.put("error", "Wrong user or token is missing");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (obj.has("from") && obj.has("to") && obj.has("message")) {

            if (temp.getToken().equals(token) && findLogin(obj.getString("to")) && findLogin(obj.getString("from"))) {
                res.put("from", obj.getString("from"));
                res.put("to", obj.getString("to"));
                res.put("message", obj.getString("message"));
                res.put("time", getTime());
                messages.add(res.toString());
                return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(res.toString());


            } else {
                res.put("error", "Wrong token or user");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

        } else
            res.put("error", "Wrong input");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }


    @RequestMapping(value = "/message")
    public ResponseEntity<String> getMessage(@RequestBody String data, @RequestHeader(name = "Authorization") String token, @RequestParam(required = false) String from) {
        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = getUser(obj.getString("login"));

        if (temp == null) {
            res.put("error", "Wrong user or token is missing");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (obj.has("login")) {
            JSONArray arr = new JSONArray();
            for (String messages : messages) {
                if (temp.getToken().equals(token) && findLogin(obj.getString("login"))) {
                    if (from == null) {
                        JSONObject temps = new JSONObject(messages);
                        arr.put(temps);


                    } else if (findLogin(from)) {


                        JSONObject temps = new JSONObject(messages);
                        if (temps.getString("from").equals(from)) {
                            arr.put(temps);
                        }
                    }
                    res.put("error", "Invalid user");
                    return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
                }

            }
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(arr.toString());
        } else
            res.put("error", "Wrong input");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());

    }


    @RequestMapping(method = RequestMethod.DELETE, value = "/delete/{login}")
    public ResponseEntity<String> deleteUser(@RequestHeader(name = "Authorization") String token, @PathVariable(required = false) String login) {

        JSONObject res = new JSONObject();
        User temp = db.getUser(login);

        if (temp == null) {
            res.put("error", "Wrong user or token is missing");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (db.checkToken(token)) {
            db.deleteUser(temp.getLogin(), token);
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(res.toString());


        }
        res.put("error", "Wrong token or login");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }

    @RequestMapping(method = RequestMethod.PATCH, value = "/update/{login}")
    public ResponseEntity<String> updateUser(@RequestBody String data, @RequestHeader(name = "Authorization") String token, @PathVariable(required = false) String login) {
        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();
        User temp = db.getUser(login);

        if (temp == null) {
            res.put("error", "Wrong user or token is missing");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        if (db.checkToken(token) && !db.findLogin(login)) {

            if (obj.has("lname") && !obj.has("fname")) {
                db.updateLname(obj.getString("lname"), token, login);
                temp.setLname(obj.getString("lname"));

            } else if (obj.has("fname") && !obj.has("lname")) {
                db.updateFname(obj.getString("fname"), token, login);
                temp.setFname(obj.getString("fname"));

            } else if (obj.has("lname") && obj.has("fname")) {
                db.updateUserBoth(obj.getString("lname"), obj.getString("fname"), token, login);
                temp.setLname(obj.getString("lname"));
                temp.setFname(obj.getString("fname"));

            }

            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }
        res.put("error", "Wrong token");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }


    private String getTime() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("ddMMyy HH:mm:ss");
        LocalDateTime localTime = LocalDateTime.now();
        return dtf.format(localTime);

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
