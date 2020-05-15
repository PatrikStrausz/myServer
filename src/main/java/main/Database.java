package main;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.json.JSONObject;
import org.json.simple.parser.JSONParser;
import org.mindrot.jbcrypt.BCrypt;

import java.io.FileReader;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class Database {

    private String url;
    private String dbName;
    private int port;

    public void getConfig(){
        JSONParser jsonParser = new JSONParser();
        try
        {
            Object obj = jsonParser.parse(new FileReader("src\\main\\java\\main\\config.json"));
            org.json.simple.JSONObject employeeList = (org.json.simple.JSONObject) obj;

             url = (String) employeeList.get("url");
             dbName = (String) employeeList.get("dbname");
             String temp = String.valueOf( employeeList.get("port"));
            port = Integer.parseInt(temp);

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public MongoClient getConnection() {
        getConfig();
        return new MongoClient(url, port);
    }


    public boolean addUser(String fname, String lname, String login, String password) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        if (findLogin(login)) {
            Document users = new Document("fname", fname)
                    .append("lname", lname)
                    .append("login", login)
                    .append("password", hashPassword(password));
            collection.insertOne(users);
            mongo.close();
            return true;
        } else {
            return false;
        }

    }


    public boolean loginUser(String login, String password) {

        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);

        Bson bsonFilter = Filters.eq("login", login);
        Document myDoc = collection.find(bsonFilter).first();
        User temp = getUser(login);

        if (myDoc != null) {

            String hashed = myDoc.getString("password");


            if (!findLogin(login) && BCrypt.checkpw(password, hashed)) {
                if (BCrypt.checkpw(password, temp.getPassword())) {
                    BasicDBObject token = new BasicDBObject().append("token", generateToken());
                    temp.setToken(token.getString("token"));
                    collection.updateOne(loginQuery, new BasicDBObject("$set", token));

                }else {
                    mongo.close();
                    return false;
                }
                mongo.close();
                return true;
            }

        }
        mongo.close();
        return false;

    }

    public boolean logoutUser(String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        loginQuery.put("token", token);

        BasicDBObject checkQuery = new BasicDBObject();
        checkQuery.append("login", login);
        checkQuery.append("token", token);

        FindIterable<Document> doc = collection.find(checkQuery);


        User temp = getUser(login);
        if (!findLogin(login) && checkToken(token))
            if (temp.getLogin().equals(login) && doc.iterator().hasNext()) {
                collection.updateOne(loginQuery, new BasicDBObject("$unset", new BasicDBObject("token", token)));
                temp.setToken(token);
                mongo.close();
            } else {
                mongo.close();
                return false;
            }
        mongo.close();
        return true;

    }

    public boolean deleteUser(String login, String token) {

        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        loginQuery.put("token", token);
        FindIterable<Document> cursor = collection.find(loginQuery);


        if (!findLogin(login) && checkToken(token)) {
            if (cursor.iterator().hasNext()) {
                collection.deleteOne(loginQuery);

            } else {
                mongo.close();
                return false;
            }
            mongo.close();
            return true;
        }
        mongo.close();
        return false;
    }

    public boolean changePassword(String oldPassword, String newPassword, String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("login", login);
        loginQuery.append("password", oldPassword);
        loginQuery.append("token", token);

        FindIterable<Document> doc = collection.find(loginQuery);

        System.out.println(doc.iterator().hasNext());
        User temp = getUser(login);

        if (checkToken(token) && !findLogin(login)) {
            if (temp.getLogin().equals(login) && doc.iterator().hasNext()) {

                collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("password", hashPassword(newPassword))));

            } else {
                mongo.close();
                return false;
            }
            mongo.close();
            return true;
        }
        mongo.close();
        return false;


    }

    public boolean updateUserBoth(String lname, String fname, String token, String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        User temp = getUser(login);
        loginQuery.append("lname", temp.getLname());
        loginQuery.append("fname", temp.getFname());
        loginQuery.append("token", token);


        if (checkToken(token) && !findLogin(login) && temp.getLogin().equals(login)) {


            collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("lname", lname).append("fname", fname)));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;
    }

    public boolean updateLname(String lname, String token, String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        User temp = getUser(login);
        loginQuery.append("lname", temp.getLname());
        loginQuery.append("token", token);

        if (checkToken(token) && !findLogin(login) && temp.getLogin().equals(login)) {

            collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("lname", lname)));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;
    }

    public boolean updateFname(String fname, String token, String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        User temp = getUser(login);
        loginQuery.append("fname", temp.getLname());
        loginQuery.append("token", token);

        System.out.println(temp.getLogin());

        if (checkToken(token) && !findLogin(login) && temp.getLogin().equals(login)) {


            collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("fname", fname)));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;
    }

    public boolean log(String login, String type) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("log");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("login", login);


        User temp = getUser(login);

        if (!findLogin(login) && temp.getLogin().equals(login)) {

            collection.insertOne(new Document().append("type", type).append("login", login)
                    .append("datetime", getTime()));
            return true;
        }
        return false;
    }

    public List<String> getLog(String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("log");

        MongoCollection<Document> collections = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("type", login);

        Bson bsonFilter = Filters.eq("login", login);
        Document myDoc = collection.find(bsonFilter).first();
        FindIterable<Document> ss = collection.find(bsonFilter);

        BasicDBObject checkQuery = new BasicDBObject();
        checkQuery.append("login", login);
        checkQuery.append("token", token);

        FindIterable<Document> doc = collections.find(checkQuery);

        User temp = getUser(login);

        List<String> tem = new ArrayList<>();
        JSONObject obj = new JSONObject();

        if (!findLogin(login) && checkToken(token) && temp.getLogin().equals(login) && myDoc != null) {
            if(doc.iterator().hasNext()) {

                for (Document p : ss) {
                    obj.put("type", p.getString("type"));
                    obj.put("login", p.getString("login"));
                    obj.put("datetime", p.getString("datetime"));
                    tem.add(obj.toString());
                }
            }else {
                return null;
            }
            return tem;
        }

return null;


    }

    public boolean newMessage(String from, String to, String token, String message) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("message");

        MongoCollection<Document> collections = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("login", from);
        loginQuery.append("token", token);

        FindIterable<Document> doc = collections.find(loginQuery);


        if (!findLogin(from) && !findLogin(to) && checkToken(token)) {
            if (doc.iterator().hasNext()) {

                collection.insertOne(new Document().append("from", from).append("to", to).append("message", message)
                        .append("time", getTime()));
            } else {
                return false;
            }
        }
        return true;


    }

    public List<String> getMessage(String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("message");

        MongoCollection<Document> collections = db.getCollection("User");


        Bson bsonFilter = Filters.eq("from", login);
        FindIterable<Document> ss = collection.find(bsonFilter);


        BasicDBObject checkQuery = new BasicDBObject();
        checkQuery.append("login", login);
        checkQuery.append("token", token);

        FindIterable<Document> doc = collections.find(checkQuery);


        List<String> tem = new ArrayList<>();
        JSONObject obj = new JSONObject();

        System.out.println(doc.iterator().hasNext());

        if (!findLogin(login) && checkToken(token)) {
            if (doc.iterator().hasNext()) {
                for (Document p : ss) {
                    obj.put("from", p.getString("from"));
                    obj.put("to", p.getString("to"));
                    obj.put("message", p.getString("message"));
                    obj.put("time", p.getString("time"));
                    tem.add(obj.toString());
                }
            }
        }

        return tem;

    }


    public String getTime() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("ddMMyy HH:mm:ss");
        LocalDateTime localTime = LocalDateTime.now();
        return dtf.format(localTime);

    }


    public User getUser(String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        Bson bsonFilter = Filters.eq("login", login);
        Document myDoc = collection.find(bsonFilter).first();


        if (!findLogin(login)) {
            assert myDoc != null;

            return new User(myDoc.getString("fname"), myDoc.getString("lname"),
                    myDoc.getString("login"), myDoc.getString("password"));

        }
        mongo.close();
        return null;

    }

    public boolean findLogin(String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        long count = collection.countDocuments(loginQuery);

        if (count == 0) {
            mongo.close();
            return true;
        }
        mongo.close();
        return false;
    }

    public boolean checkToken(String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("token", token);

        long count = collection.countDocuments(loginQuery);
        if (count > 0) {
            mongo.close();
            return true;
        }
        mongo.close();
        return false;

    }

    public String getToken(String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase(dbName);
        MongoCollection<Document> collection = db.getCollection("User");

        Bson bsonFilter = Filters.eq("login", login);
        Document myDoc = collection.find(bsonFilter).first();


        if (!findLogin(login)) {
            assert myDoc != null;
            return myDoc.getString("token");
        }
        return null;

    }

    private String generateToken() {
        return Long.toString(Math.abs(new SecureRandom().nextLong()), 16);

    }

    private String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));

    }


}
