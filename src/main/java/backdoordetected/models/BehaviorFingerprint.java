package backdoordetected.models;

import java.util.Set;

public record BehaviorFingerprint(
    int networkCallCount,
    int fileIOCount,
    int reflectionCallCount,
    int cryptoOperationCount,
    double stringEntropy,
    Set<String> externalDomains
) {
    public boolean isSuspicious() {
        return (networkCallCount > 2 && reflectionCallCount > 5) ||
               (networkCallCount > 5) || (reflectionCallCount > 10) || (stringEntropy > 4.5 && cryptoOperationCount > 0);
    }
}