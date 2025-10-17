package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class C0Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("C0 Test")
    @Test
    void C0_TEST() {
        String result = jobProcess.processC0("90000000000000199FE3BF381FA0911C40464FF6422A66B5B8944C0CDB06DC5FD0F58C09749A44DDF980B37F242464B92EA2B22C808E230701");

        log.info("result={}", result);
        String resCode = "00000000";
        String pwd = "1234    ";

        String expect = resCode + pwd;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
