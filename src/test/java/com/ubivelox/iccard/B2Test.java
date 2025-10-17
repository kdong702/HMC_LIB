package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class B2Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("B2 40키로 Test_임시 FCI 데이터 CSN 확인 필요")
    @Test
    void key_40() {
        String result = jobProcess.processB2("013333333333333333222222222222222222222222222222223333333333333333333333333301DDDDDDDDDDDDD555555556666");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC010C4B65455F201A33333333333333333333333333333333333333333333333333334B0E01444444444444444444444444445F240455555555C20100C3026666C4083333333333333333";
        String mac = "AEA4B18B";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertNotEquals(expect, result);
    }

    @DisplayName("B2 홍길동 테스트")
    @Test
    void key_origin() {
        String result = jobProcess.processB2("019263141187048110A8044E2F7E176A703B8E672E2D02CA94홍길동                    05             300001010263");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC010C4B65455F201AC8ABB1E6B5BF20202020202020202020202020202020202020204B0E05000000000000000000000000005F240430000101C20100C3020263C4089263141187048110";
        String mac = "4166220E";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
