package com.ubivelox.iccard;


import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class A1Test {

    JobProcess jobProcess = new JobProcess();

    @Test
    @BeforeEach
    public void initialLib() {
        jobProcess.initLibrary();
    }

//    @DisplayName("A2 SCP2 Test")
//    @Test
//    void scp2_Success() {
//        String result = jobProcess.processA1("000000000000000000002067090CA08E145402020000807BEFC78BA0563C2A9FD4411362");
//        log.info("result={}", result);
//        String resCode = "00000000";
//        String authApdu = "8482000010006AE8613407E3ABDDA53E229577596D";
//        String cmkApdu = "80D80281430180102A7B7D31621CDD7D9E9393E253F9E80B033F7BCA80102EF9848E45163374526F37C4627B33BD03FA204B80106467D7CE324C5887AFCDDA06B46671290345D19A";
//        String expect = resCode + authApdu + cmkApdu;
//        log.info("expect={}", expect);
//        Assertions.assertEquals(expect, result);
//    }


    @DisplayName("A1 SCP2 초기키 성공 Test")
    @Test
    void scp2_INIT_40() {
        String result = jobProcess.processA1("313131313131313100002067090CA08C1454010200014C7C610AA0ACC20CD8C31BE4A52B");
        log.info("result={}", result);
        String resCode = "00000000";
        String authApdu = "84820000103732A640F5E92CCA84DF42879E7BCE4C";
        String expect = resCode + authApdu;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }

    @DisplayName("A1 SCP2 초기키 실패후 은행키 Test")
    @Test
    void scp2_INIT_FAIL_BANK_50() {
        String result = jobProcess.processA1("313131313131313100002067090CA08C1454010200013C5DEE96496FB33A453B65AD237C");
        log.info("result={}", result);
        String resCode = "00000000";
        String authApdu = "84820000103B043B6D1CACFA98EBEB539AEC3D421D";

        String expect = resCode + authApdu;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result);
    }

    @DisplayName("A1 SCP2 CC 검증 실패")
    @Test
    void scp2_CC_FAIL() {
        String result = jobProcess.processA1("313131313131313100002067090CA08C1454010200013C5DEE96496FB33A453B65AD237D");
        log.info("result={}", result);
        String resCode = "HD300008";
        String expect = resCode;
        log.info("expect={}", expect);
        Assertions.assertEquals(expect, result.substring(0, 8));
    }

    @DisplayName("A1 SCP1 Test")
    @Test
    void scp1_Success() {
        String result = jobProcess.processA1("000000000000000000002067090CA08E145401010000807BEFC78BA0e9cfa0f85f45fb17");
        log.info("result={}", result);
        String resCode = "00000000";
        String authApdu = "84820000105B7EACFB677F7269A56F36CC4CCDE47F";
        String expect = resCode + authApdu;
        log.info("expect={}", expect);
        Assertions.assertEquals(result, expect);
    }

    @DisplayName("0 Test")
    @Test
    void zero_test() {
        String result = jobProcess.processA1("000000000000000000000000000000000000000000000000000000000000000000000000");
        log.info("result={}", result);
        String resCode = "00000000";
        String authApdu = "000000000000000000000000000000000000000000";
        String expect = resCode + authApdu;
        log.info("expect={}", expect);
        Assertions.assertEquals(result, expect);
    }
}
