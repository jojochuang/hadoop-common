package org.apache.hadoop.tools.kmsreplay;

import com.google.common.base.Splitter;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimpleKMSAuditLogParser implements KMSAuditParser{
  private static final Logger LOG =
      LoggerFactory.getLogger(SimpleKMSAuditLogParser.class);
  // 2019-04-22 00:00:20,949 OK[op=DECRYPT_EEK, key=paypal_emea_key, user=cds_user, accessCount=2082, interval=1122180ms]
  public static final String AUDIT_START_TIMESTAMP_KEY =
      "auditreplay.log-start-time.ms";

  private static final Pattern MESSAGE_ONLY_PATTERN = Pattern
      .compile("^([0-9-]+ [0-9:,]+) (.+)$");
  private static final Splitter.MapSplitter AUDIT_SPLITTER = Splitter.on(",")
      .trimResults().omitEmptyStrings().withKeyValueSeparator("=");
  private static final Pattern AUDIT_DETAILS_PATTERN =
      Pattern.compile("^OK\\[(.+)].*$");
  static final DateFormat AUDIT_DATE_FORMAT = new SimpleDateFormat(
      "yyyy-MM-dd HH:mm:ss,SSS");

  private long startTimestamp;

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
    Matcher m = MESSAGE_ONLY_PATTERN.matcher(inputLine.toString());
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
    LOG.info("timestamp=" +relativeTimestamp);

    String details = m.group(2);
    // parse only authorized audits. Unauthorized audits don't carry details and can't be replayed.
    Matcher m2 = AUDIT_DETAILS_PATTERN.matcher(details);
    if (!m2.find()) {
      LOG.warn("invalid audit log entry: " + details);
      return null;
    }
    String auditMessageSanitized = m2.group(1);
    Map<String, String> parameterMap = AUDIT_SPLITTER
        .split(auditMessageSanitized);

    String accessCountString = parameterMap.get("accessCount");
    int accessCount = 0;
    if (accessCountString != null) {
      accessCount = Integer.parseInt(accessCountString);
    }

    String intervalString = parameterMap.get("interval");
    int interval = 0;
    if (intervalString != null ) {
      interval = Integer.parseInt(intervalString.substring(0, intervalString.length()-2));
    }

    return new AuditReplayCommand(
        relativeToAbsolute.apply(relativeTimestamp),
        parameterMap.get("op"),
        parameterMap.get("key"),
        parameterMap.get("user"),
        accessCount,
        interval);
  }
}
