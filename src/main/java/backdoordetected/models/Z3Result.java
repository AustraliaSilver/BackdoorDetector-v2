package backdoordetected.models;

import com.microsoft.z3.Status;
import java.util.Map;
import java.util.Collections;

public record Z3Result(
        Status status, 
        String explanation, 
        Map<String, String> model 
) {
    
    public boolean isBackdoorConfirmed() {
        return status == Status.SATISFIABLE;
    }

    
    public static Z3Result confirmed(String explanation, Map<String, String> model) {
        return new Z3Result(Status.SATISFIABLE, explanation, model);
    }

    
    public static Z3Result unreachable(String explanation) {
        return new Z3Result(Status.UNSATISFIABLE, explanation, Collections.emptyMap());
    }

    
    public static Z3Result unknown(String explanation) {
        return new Z3Result(Status.UNKNOWN, explanation, Collections.emptyMap());
    }

    @Override
    public String toString() {
        if (isBackdoorConfirmed()) {
            return String.format("BACKDOOR CONFIRMED: %s\\nExample trigger: %s", explanation, model);
        } else {
            return String.format("%s: %s", status, explanation);
        }
    }
}
