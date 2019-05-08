package org.apache.hadoop.crypto.key;

import io.jaegertracing.internal.JaegerTracer;
import io.opentracing.Scope;
import io.opentracing.SpanContext;
import io.opentracing.Tracer;
import io.opentracing.util.GlobalTracer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.tracing.StringCodec;
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

  private static final String NULL_SPAN_AS_STRING = "";


  /**
   * Export the active tracing span as a string.
   *
   * @return encoded tracing context.
   */
  public static String exportCurrentSpan() {
    if (GlobalTracer.get().activeSpan() != null) {
      StringBuilder builder = new StringBuilder();
      GlobalTracer.get().inject(GlobalTracer.get().activeSpan().context(),
          StringCodec.FORMAT, builder);
      return builder.toString();
    }
    return NULL_SPAN_AS_STRING;
  }

  /**
   * Create a new scope and use the imported span as the parent.
   *
   * @param name          name of the newly created scope
   * @param encodedParent Encoded parent span (could be null or empty)
   *
   * @return OpenTracing scope.
   */
  public static Scope importAndCreateScope(String name, String encodedParent) {
    Tracer.SpanBuilder spanBuilder;
    Tracer tracer = GlobalTracer.get();
    SpanContext parentSpan = null;
    if (encodedParent != null && encodedParent.length() > 0) {
      StringBuilder builder = new StringBuilder();
      builder.append(encodedParent);
      parentSpan = tracer.extract(StringCodec.FORMAT, builder);

    }

    if (parentSpan == null) {
      spanBuilder = tracer.buildSpan(name);
    } else {
      spanBuilder =
          tracer.buildSpan(name).asChildOf(parentSpan);
    }
    return spanBuilder.startActive(true);
  }
}
