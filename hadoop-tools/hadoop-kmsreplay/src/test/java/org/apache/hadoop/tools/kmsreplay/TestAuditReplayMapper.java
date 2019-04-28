package org.apache.hadoop.tools.kmsreplay;

import org.apache.hadoop.conf.Configuration;
import org.junit.Test;

import static org.junit.Assert.*;

public class TestAuditReplayMapper {

  @Test
  public void initTracing() {
    AuditReplayMapper mapper = new AuditReplayMapper();
    Configuration conf = new Configuration();

    conf.set("JAEGER_AGENT_HOST", "localhost");
    conf.set("JAEGER_AGENT_PORT", "6831");

    TracerUtil.initTracing(conf, "kms-o-meter");
  }
}