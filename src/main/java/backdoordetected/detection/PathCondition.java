package backdoordetected.detection;

import java.util.Objects;
import java.util.regex.Pattern;

public class PathCondition {

    public enum ConditionType {
        REGEX_MATCH,
        TYPE_CHECK,
        NULL_CHECK,
        WHITELIST,
        LENGTH_CHECK,
        CUSTOM,
        NONE
    }

    private final ConditionType type;
    private final String pattern;
    private final String variable;
    private final boolean negated;

    public PathCondition(ConditionType type, String variable, String pattern, boolean negated) {
        this.type = type;
        this.variable = variable;
        this.pattern = pattern;
        this.negated = negated;
    }

    public static PathCondition none() {
        return new PathCondition(ConditionType.NONE, null, null, false);
    }

    public static PathCondition regexMatch(String variable, String pattern, boolean negated) {
        return new PathCondition(ConditionType.REGEX_MATCH, variable, pattern, negated);
    }

    public static PathCondition nullCheck(String variable, boolean negated) {
        return new PathCondition(ConditionType.NULL_CHECK, variable, null, negated);
    }

    public static PathCondition whitelist(String variable, boolean negated) {
        return new PathCondition(ConditionType.WHITELIST, variable, null, negated);
    }

    public static PathCondition lengthCheck(String variable, String maxLength, boolean negated) {
        return new PathCondition(ConditionType.LENGTH_CHECK, variable, maxLength, negated);
    }

    public boolean validates(String taintedVar) {
        if (type == ConditionType.NONE || negated) {
            return false;
        }
        if (variable == null || !variable.equals(taintedVar)) {
            return false;
        }
        switch (type) {
            case REGEX_MATCH:
                return isStrongRegex(pattern);
            case NULL_CHECK:
                return false;
            case WHITELIST:
                return true;
            case LENGTH_CHECK:
                return false;
            case TYPE_CHECK:
                return false;
            default:
                return false;
        }
    }

    private boolean isStrongRegex(String regex) {
        if (regex == null)
            return false;
        String[] strongPatterns = {
                "\\[a-zA-Z0-9\\]+",
                "\\[a-z\\]+",
                "\\[A-Z\\]+",
                "\\[0-9\\]+",
                "\\[a-zA-Z\\]+",
                "\\\\d+",
                "\\\\w+"
        };

        for (String strong : strongPatterns) {
            if (regex.contains(strong)) {
                return true;
            }
        }

        return false;
    }

    public PathCondition negate() {
        return new PathCondition(type, variable, pattern, !negated);
    }

    public PathCondition merge(PathCondition other) {
        if (this.type == ConditionType.NONE || other.type == ConditionType.NONE) {
            return PathCondition.none();
        }
        if (this.equals(other.negate())) {
            return PathCondition.none();
        }
        if (this.equals(other)) {
            return this;
        }
        if (this.variable != null && this.variable.equals(other.variable)) {
            if (this.type == ConditionType.WHITELIST || this.type == ConditionType.REGEX_MATCH) {
                return this;
            }
            if (other.type == ConditionType.WHITELIST || other.type == ConditionType.REGEX_MATCH) {
                return other;
            }
        }

        return PathCondition.none();
    }

    public ConditionType getType() {
        return type;
    }

    public String getVariable() {
        return variable;
    }

    public String getPattern() {
        return pattern;
    }

    public boolean isNegated() {
        return negated;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        PathCondition that = (PathCondition) o;
        return negated == that.negated &&
                type == that.type &&
                Objects.equals(pattern, that.pattern) &&
                Objects.equals(variable, that.variable);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, pattern, variable, negated);
    }

    @Override
    public String toString() {
        if (type == ConditionType.NONE) {
            return "PathCondition[NONE]";
        }
        return String.format("PathCondition[%s, var=%s, pattern=%s, negated=%s]",
                type, variable, pattern, negated);
    }
}
