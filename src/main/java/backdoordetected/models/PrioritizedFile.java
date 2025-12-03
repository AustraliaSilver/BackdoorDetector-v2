package backdoordetected.models;

import java.io.File;

public record PrioritizedFile(File file, int priority) implements Comparable<PrioritizedFile> {
  @Override
  public int compareTo(PrioritizedFile other) {
    return Integer.compare(other.priority, this.priority);
  }
}
