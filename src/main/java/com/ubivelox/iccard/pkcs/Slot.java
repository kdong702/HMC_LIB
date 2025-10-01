package com.ubivelox.iccard.pkcs;


import com.ubivelox.iccard.common.Constants;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Slot {
    // 슬롯 라벨
    private String label;
    // 슬롯 long id
    private long id;
    // 슬롯 비밀번호
    private String slotPassword;
    // 슬롯 현재 사용중 세션 -> 없으면 0
    private long sessionId;
    // 슬롯 토큰 라벨
    private String tokenLabel;
    // 마지막 사용 내용
    private long lastUsedTime;
    // 상태
    private String status = Constants.NO;

    public Slot(String label, String slotPassword, long sessionId) {
        this.label = label;
        this.slotPassword = slotPassword;
        this.sessionId = sessionId;
    }
}
