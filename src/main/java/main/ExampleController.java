package main;

import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class ExampleController {
    @RequestMapping("/hello")
    public String getHello() {
        return "Hello.";
    }

    @RequestMapping("/hello/{name}")
    public String getHelloName(@PathVariable String name) {
        return "Hello " + name;
    }

    @RequestMapping("/hi")
    public String getHi(@RequestParam(value = "fname") String name, @RequestParam(value = "lname") String lname, @RequestParam(value = "city") String city) {

        return name + " " + lname + "\n" + city;
    }


    @RequestMapping("/primenumber/{number}")
    public ResponseEntity<String> checkPrimeNumber(@PathVariable int number) {
        try {
            boolean isPrimeNumber = true;
            if (number > 1) {

                for (int j = 2; j <= Math.sqrt(number); j++)
                    if (number % j == 0) {
                        isPrimeNumber = false;
                        break;
                    }
            } else
                isPrimeNumber = false;

            JSONObject res = new JSONObject();
            res.put("number", number);
            res.put("primenumber", isPrimeNumber);

            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        } catch (NumberFormatException e) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Param must be integer\"}");
        }

    }


}


