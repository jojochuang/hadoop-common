package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.function.Function;

public class SimpleKMSAuditLogParser implements KMSAuditParser{
  public static final String AUDIT_START_TIMESTAMP_KEY =
      "auditreplay.log-start-time.ms";
  private long startTimestamp;

  private static final DateFormat AUDIT_DATE_FORMAT = new SimpleDateFormat(
      "yyyy-MM-dd hh:mm:ss,SSS");
  static {
    AUDIT_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  @Override
  public void initialize(Configuration conf) throws IOException {
    startTimestamp = conf.getLong(AUDIT_START_TIMESTAMP_KEY, -1);
    if (startTimestamp < 0) {
      throw new IOException(
          "Invalid or missing audit start timestamp: " + startTimestamp);
    }
  }

  @Override
  public AuditReplayCommand parse(Text inputLine,
      Function<Long, Long> relativeToAbsolute) throws IOException {
    /*Matcher m = MESSAGE_ONLY_PATTERN.matcher(inputLine.toString());
    if (!m.find()) {
      throw new IOException(
          "Unable to find valid message pattern from audit log line: "
              + inputLine);
    }
    long relativeTimestamp;
    try {
      relativeTimestamp = AUDIT_DATE_FORMAT.parse(m.group(1)).getTime()
          - startTimestamp;
    } catch (ParseException p) {
      throw new IOException("Exception while parsing timestamp from audit log",
          p);
    }
    // We sanitize the = in the rename options field into a : so we can split on
    // =
    String auditMessageSanitized = m.group(2).replace("(options=", "(options:");
    Map<String, String> parameterMap = AUDIT_SPLITTER
        .split(auditMessageSanitized);
    return new AuditReplayCommand(relativeToAbsolute.apply(relativeTimestamp),
        // Split the UGI on space to remove the auth and proxy portions of it
        SPACE_SPLITTER.split(parameterMap.get("ugi")).iterator().next(),
        parameterMap.get("cmd").replace("(options:", "(options="),
        parameterMap.get("src"), parameterMap.get("dst"),
        parameterMap.get("ip"));*/
  }
}
