package main;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.mindrot.jbcrypt.BCrypt;

import java.security.SecureRandom;

public class Database {

    public MongoClient getConnection() {
        return new MongoClient("localhost", 27017);
    }


    public boolean addUser(String fname, String lname, String login, String password) {


        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
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
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);

        Bson bsonFilter = Filters.eq("login", login);
        Document myDoc = collection.find(bsonFilter).first();

        assert myDoc != null;
        String hashed = myDoc.getString("password");
        User temp = getUser(login);

        if (!findLogin(login) && BCrypt.checkpw(password, hashed) && temp.getLogin().equals(login)) {
            BasicDBObject token = new BasicDBObject().append("token", generateToken());
            temp.setToken(token.getString("token"));
            collection.updateOne(loginQuery, new BasicDBObject("$set", token));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;

    }

    public boolean logoutUser(String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        loginQuery.put("token", token);

        User temp = getUser(login);
        if (!findLogin(login) && checkToken(token) && temp.getLogin().equals(login)) {
            collection.updateOne(loginQuery, new BasicDBObject("$unset", new BasicDBObject("token", token)));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;

    }

    public boolean deleteUser(String login, String token) {

        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        loginQuery.put("token", token);
        MongoCursor<Document> cursor = collection.find(loginQuery).iterator();

        User temp = getUser(login);

        if (cursor.hasNext() && temp.getLogin().equals(login)) {
            collection.deleteOne(loginQuery);
            mongo.close();
            return true;
        }
        mongo.close();
        return false;


    }

    public boolean changePassword(String oldPassword, String newPassword, String login, String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.append("login", login);
        loginQuery.append("password", oldPassword);
        loginQuery.append("token", token);

        User temp = getUser(login);

        if (checkToken(token) && !findLogin(login) && temp.getLogin().equals(login)) {

            collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("password", hashPassword(newPassword))));
            mongo.close();
            return true;
        }
        mongo.close();
        return false;


    }

    public boolean updateUserBoth(String lname, String fname, String token, String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
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
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");


        BasicDBObject loginQuery = new BasicDBObject();
        User temp = getUser(login);
        loginQuery.append("lname", temp.getLname());
        loginQuery.append("token", token);

        System.out.println(temp.getLogin());

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
        MongoDatabase db = mongo.getDatabase("Bank");
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


    public User getUser(String login) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
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
        MongoDatabase db = mongo.getDatabase("Bank");
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

    public boolean checkPassword(String login, String password) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
        MongoCollection<Document> collection = db.getCollection("User");

        BasicDBObject loginQuery = new BasicDBObject();
        loginQuery.put("login", login);
        loginQuery.put("password", password);
        User temp = getUser(login);


        if (!findLogin(login) ) {
            mongo.close();
            return BCrypt.checkpw(password, temp.getPassword());
        }
        mongo.close();
        return false;
    }

    public boolean checkToken(String token) {
        MongoClient mongo = getConnection();
        MongoDatabase db = mongo.getDatabase("Bank");
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
        MongoDatabase db = mongo.getDatabase("Bank");
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
