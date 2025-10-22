package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class C1Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }


    @DisplayName("C1 Test")
    @Test
    void C1_TEST() {
        String result = jobProcess.processC1("9263141187048110E8401EA79B780BE43DD9887589F7AE3BC1667EBB96D1022CE900BA88EA14E63731313131313131313131313131313131CC9561665327EC2E567EB59C3E0D995647995DF90BEF74AF4EDECC2F898B714A06CFFE404CE774117F1BE50B41BED11D01");

        log.info("result={}", result);
        String resCode = "00000000";
        String pwd = "1234";
        String accountNum = "22010664        ";
        String accountMount = "15999           ";
        String expect = resCode + pwd + accountNum + accountMount;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }
}
