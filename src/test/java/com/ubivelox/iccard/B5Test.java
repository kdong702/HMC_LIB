package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class B5Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("B5 Test")
    @Test
    void key_40() {
        String result = jobProcess.processB5("019263141187048110B81A7FEACA6E7F1AE130444AC815FDD9498949  ");
//        String result = jobProcess.processB5("015898336179900016E23D129045B286F7A05D4BB6C4651C015BD3BE9D7042F0D3");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "A4240101142A3C8917FB6AE55A345ECD24D906DC1B";
        String mac = "29547200";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
