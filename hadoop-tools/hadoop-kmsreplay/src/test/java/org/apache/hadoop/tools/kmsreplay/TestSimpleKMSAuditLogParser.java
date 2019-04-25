package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.junit.Test;

import java.io.IOException;
import java.util.function.Function;

import static org.apache.hadoop.tools.kmsreplay.SimpleKMSAuditLogParser.AUDIT_START_TIMESTAMP_KEY;
import static org.junit.Assert.*;

public class TestSimpleKMSAuditLogParser {

  @Test
  public void parse() throws IOException {
    Configuration conf = new Configuration();
    long startTimestampMs = 0;
    conf.setLong(AUDIT_START_TIMESTAMP_KEY, startTimestampMs);
    SimpleKMSAuditLogParser parser = new SimpleKMSAuditLogParser();
    parser.initialize(conf);

    Function<Long, Long> relativeToAbsoluteTimestamp =
        (input) -> startTimestampMs + Math.round(input);

    Text sampleAuditLog = new Text("2019-04-22 00:00:20,949 OK[op=DECRYPT_EEK, key=paypal_emea_key, user=cds_user, accessCount=2082, interval=1122180ms]");
    AuditReplayCommand command = parser.parse(sampleAuditLog, relativeToAbsoluteTimestamp);

    assertEquals("Unexpected command", "DECRYPT_EEK", command.getCommand());
    assertEquals("Unexpected key", "paypal_emea_key", command.getKey());
    assertEquals("Unexpected user", "cds_user", command.getUser());
    assertEquals("Unexpected access count", 2082, command.getAccessCount());
    assertEquals("Unexpected interval", 1122180, command.getInterval());

    Text unathenticatedAuditLog = new Text("2019-04-22 00:00:34,424 UNAUTHENTICATED RemoteHost:10.233.81.64 Method:POST URL:http://pc1udtlhmem08.prodc1.harmony.global:16000/kms/v1/keyversion/poJI4xFu8oLZapU5xOm3r43s1UEYWzYNAclwEgLNwp3/_eek?eek_op=decrypt ErrorMsg:'AuthenticationToken expired'");
    AuditReplayCommand unauthenticatedCommand = parser.parse(unathenticatedAuditLog, relativeToAbsoluteTimestamp);
    assertEquals("The audit log is unauthenticated", null, unauthenticatedCommand);
  }
}