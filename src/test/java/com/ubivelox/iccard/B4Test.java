package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class B4Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("B4 키 버전 01")
    @Test
    void key_01() {
        String result = jobProcess.processB4("01999999999999999931313131313131312121212121212121");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "A424000114B12C98C2342AB81B03D2A23905097191";
        String mac = "BEC4DDEA";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }

    @DisplayName("B4 키 버전 00")
    @Test
    void key_00_1() {
        String result = jobProcess.processB4("00999999999999999931313131313131312121212121212121");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "A42400011430C8D5890B6D11B7A7B81783E5229D34";
        String mac = "51CF9B11";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }

    @DisplayName("B4 키 버전 00_2")
    @Test
    void key_00_2() {
        String result = jobProcess.processB4("00926314118704811094BBEECCEDF805E3459AEFB0C031B2F8");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "A424000114456D555F01EA3A66C9E332208FFA37FE";

        String mac = "29032670";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
