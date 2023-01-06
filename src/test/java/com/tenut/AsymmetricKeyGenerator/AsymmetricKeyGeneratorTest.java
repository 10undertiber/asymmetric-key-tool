package com.tenut.AsymmetricKeyGenerator;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class AsymmetricKeyGeneratorTest {
    @Test
    public void shouldAnswerWithTrue() {
        AsymmetricKeyPair key = AsymmetricKeyGenerator.newKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_R256);
        assertNotNull(key);
    }
}
