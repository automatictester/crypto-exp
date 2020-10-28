package uk.co.automatictester.security.random;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import java.security.SecureRandom;
import java.util.Random;

@Slf4j
public class RandomTest {

    // given same seed, same output will be generated
    @Test(invocationCount = 2)
    public void testRandom() {
        Random random = new Random();
        random.setSeed(20);
        log.info("{}:", random.getClass());
        for (int i = 0; i < 5; i++) {
            log.info("{}", random.nextInt());
        }
    }

    // given same seed, different output will be generated
    @Test(invocationCount = 2)
    public void testSecureRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(20);
        log.info("{}:", random.getClass());
        for (int i = 0; i < 5; i++) {
            log.info("{}", random.nextInt());
        }
    }
}
