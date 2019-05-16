package org.apache.hadoop.tools.kmsreplay;

import com.google.common.base.Joiner;
import com.google.common.base.Strings;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;

import static org.apache.hadoop.tools.kmsreplay.SimpleKMSAuditLogParser.AUDIT_DATE_FORMAT;

public class AuditReplayCommand implements Delayed {
  private long absoluteTimestamp;
  private String ugi;
  private String command;
  private String key;
  private int accessCount;
  private int interval;

  AuditReplayCommand(long absoluteTimestamp, String command,
      String key, String ugi, int accessCount, int interval) {
    this.absoluteTimestamp = absoluteTimestamp;
    this.command = command;
    this.key = key;
    this.ugi = ugi;
    this.accessCount = accessCount;
    this.interval = interval;
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

  public int getAccessCount() {
    return accessCount;
  }

  public int getInterval() {
    return interval;
  }

  public void setAccessCount(int accessCount) {
    this.accessCount = accessCount;
  }

  /**
   * A command representing a Poison Pill, indicating that the processing thread
   * should not process any further items and instead should terminate itself.
   * Always returns true for {@link #isPoison()}. It does not contain any other
   * information besides a timestamp; other getter methods wil return null.
   */
  private static final class PoisonPillCommand extends AuditReplayCommand {

    private PoisonPillCommand(long absoluteTimestamp) {
      super(absoluteTimestamp, null, null, null, 0, 0);
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
        && command.equals(o.command) && key.equals(o.key) && accessCount == o.accessCount
        && interval == o.interval;
  }

  @Override
  public int hashCode() {
    return Objects.hash(absoluteTimestamp, ugi, command, key, accessCount, interval);
  }

  @Override
  public String toString() {
    return String.format("AuditReplayCommand(absoluteTimestamp=%d, ugi=%s, "
            + "command=%s, key=%s, accessCount=%d, interval=%d",
        absoluteTimestamp, ugi, command, key, accessCount, interval);
  }

  public String print() {
    Date date = new Date(absoluteTimestamp);
    final List<String> kvs = new LinkedList<>();
    if (command != null) {
      kvs.add("op=" + command);
    }
    if (!Strings.isNullOrEmpty(key)) {
      kvs.add("key=" + key);
    }
    if (!Strings.isNullOrEmpty(ugi)) {
      kvs.add("user=" + ugi);
    }

    if (accessCount > 0) {
      kvs.add("accessCount=" + accessCount);
      kvs.add("interval=" + interval + "ms");
    }
    /*f (kvs.isEmpty()) {
      //auditLog.info("{} {}", status, event.getExtraMsg());
      return String.format("%s OK[op=%s, key=%s, user=%s, accessCount=%d, interval=%dms]\n",
          AUDIT_DATE_FORMAT.format(date),
          command, key, ugi, accessCount, interval);
    } else {*/
      final String join = Joiner.on(", ").join(kvs);
      //auditLog.info("{}[{}] {}", status, join, event.getExtraMsg());
    return String.format("%s OK[%s] \n",
        AUDIT_DATE_FORMAT.format(date),
        join);
    /*}*/



  }
}
