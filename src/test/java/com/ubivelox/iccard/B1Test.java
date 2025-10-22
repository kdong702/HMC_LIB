package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class B1Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("B1 CASE1 Test")
    @Test
    void case01() {
        String result = jobProcess.processB1("01999999999999999931313131313131312121212121212121HMSEC           ");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC01F42E6F288407D4106509900010A51D5010484D5345432020202020202020202020BF0C080101000000000000";
        String mac = "8BA323F1";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }

    @DisplayName("B1 CASE2 Test")
    @Test
    void case02() {
        String result = jobProcess.processB1("0192631411870481104ABDE553A3CC0E159644457C79D7B08A1411870 증권    ");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC01F42E6F288407D4106509900010A51D50103134313138373020C1F5B1C720202020BF0C080101000000000000";
        String mac = "97FFC4D8";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
