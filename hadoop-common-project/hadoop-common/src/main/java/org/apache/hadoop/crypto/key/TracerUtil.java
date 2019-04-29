package org.apache.hadoop.crypto.key;

import io.jaegertracing.internal.JaegerTracer;
import io.opentracing.util.GlobalTracer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TracerUtil extends Configured implements Tool {
  private static final Logger LOG =
      LoggerFactory.getLogger(TracerUtil.class);

  public static void main(String[] args) throws Exception {
    TracerUtil driver = new TracerUtil();
    System.exit(ToolRunner.run(driver, args));
  }

  @Override
  public int run(String[] args) throws Exception {
    initTracing(getConf(), "test tracer");
    return 0;
  }
  /**
   * Initialize the tracing with the given service name.
   *
   * @param serviceName
   */
  public static void initTracing(Configuration conf, String serviceName) {
    System.setProperty("JAEGER_SAMPLER_PARAM", "1");
    String jaegerAgentHost = conf.get("JAEGER_AGENT_HOST", "");
    String jaegerAgentPort = conf.get("JAEGER_AGENT_PORT", "6831");

    System.setProperty("JAEGER_AGENT_HOST", jaegerAgentHost);
    System.setProperty("JAEGER_AGENT_PORT", jaegerAgentPort);

    LOG.info("Jaeger agent host:port = " + jaegerAgentHost + ":" + jaegerAgentPort);

    if (!GlobalTracer.isRegistered()) {
      io.jaegertracing.Configuration config = io.jaegertracing.Configuration.fromEnv(serviceName);
      JaegerTracer tracer = config.getTracerBuilder().registerExtractor(StringCodec.FORMAT, new StringCodec())
          .registerInjector(StringCodec.FORMAT, new StringCodec()).build();
      GlobalTracer.register(tracer);
    }
  }
}
