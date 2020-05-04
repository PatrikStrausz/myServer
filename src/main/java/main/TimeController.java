package main;

import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class TimeController {

    @RequestMapping("/time/hour")
    public ResponseEntity<String> getHour() {
        JSONObject res = new JSONObject();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH");
        LocalDateTime localTime = LocalDateTime.now();
        String time = dtf.format(localTime);
        res.put("hour", time);
        return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }
}
