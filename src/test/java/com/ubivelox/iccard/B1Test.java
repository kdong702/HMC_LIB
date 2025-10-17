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


    @DisplayName("B1 40키로 Test")
    @Test
    void key_40() {
        String result = jobProcess.processB1("01999999999999999921212121212121212121212121212121HMSEC           ");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC01F42E6F288407D4106509900010A51D5010484D5345432020202020202020202020BF0C080101000000000000";
        String mac = "DB1FB732";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
