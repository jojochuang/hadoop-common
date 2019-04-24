package org.apache.hadoop.tools.kmsreplay;

import java.util.Objects;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

public class AuditReplayCommand implements Delayed {
  private long absoluteTimestamp;
  private String ugi;
  private String command;
  private String key;

  AuditReplayCommand(long absoluteTimestamp, String ugi, String command/*,
      String src, String dest, String sourceIP*/) {
    this.absoluteTimestamp = absoluteTimestamp;
    this.ugi = ugi;
    this.command = command;
    /*this.src = src;
    this.dest = dest;
    this.sourceIP = sourceIP;*/
  }

  long getAbsoluteTimestamp() {
    return absoluteTimestamp;
  }

  String getUser() {
    return ugi;
  }

  String getCommand() {
    return command;
  }

  @Override
  public long getDelay(TimeUnit unit) {
    return unit.convert(absoluteTimestamp - System.currentTimeMillis(),
        TimeUnit.MILLISECONDS);
  }

  @Override
  public int compareTo(Delayed o) {
    return Long.compare(absoluteTimestamp,
        ((AuditReplayCommand) o).absoluteTimestamp);
  }

  /**
   * If true, the thread which consumes this item should not process any further
   * items and instead simply terminate itself.
   */
  boolean isPoison() {
    return false;
  }

  public String getKey() {
    return key;
  }

  /**
   * A command representing a Poison Pill, indicating that the processing thread
   * should not process any further items and instead should terminate itself.
   * Always returns true for {@link #isPoison()}. It does not contain any other
   * information besides a timestamp; other getter methods wil return null.
   */
  private static final class PoisonPillCommand extends AuditReplayCommand {

    private PoisonPillCommand(long absoluteTimestamp) {
      super(absoluteTimestamp, null, null/*, null, null, null*/);
    }

    @Override
    boolean isPoison() {
      return true;
    }

  }

  static AuditReplayCommand getPoisonPill(long relativeTimestamp) {
    return new PoisonPillCommand(relativeTimestamp);
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof AuditReplayCommand)) {
      return false;
    }
    AuditReplayCommand o = (AuditReplayCommand) other;
    return absoluteTimestamp == o.absoluteTimestamp && ugi.equals(o.ugi)
        && command.equals(o.command) /*&& src.equals(o.src) && dest.equals(o.dest)
        && sourceIP.equals(o.sourceIP)*/;
  }

  @Override
  public int hashCode() {
    return Objects.hash(absoluteTimestamp, ugi, command/*, src, dest, sourceIP*/);
  }

  @Override
  public String toString() {
    return String.format("AuditReplayCommand(absoluteTimestamp=%d, ugi=%s, "
            + "command=%s, src=%s, dest=%s, sourceIP=%s",
        absoluteTimestamp, ugi, command/*, src, dest, sourceIP*/);
  }
}
