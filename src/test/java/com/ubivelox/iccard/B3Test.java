package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class B3Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }



    @DisplayName("B3 테스트")
    @Test
    void key_origin() {
        String result = jobProcess.processB3("01926314118704811005AB2C05C96245B21DB5DD2B780A471801010159263=22010664000000000=4104103000000000000000200000100000012991=00000000000000000==0=22010664000000020108");
        log.info("result={}", result);
        String resCode = "00000000";
        String updateApdu = "04DC011444C13E01B0159263D22010664000000000D4104103000000000000000200000100000012991D00000000000000000DD0D2201066400000002F0001080000000000";
        String mac = "CE5DA143";
        String expect = resCode + updateApdu + mac;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
