package org.apache.hadoop.tracing;

public abstract class Tracer {
  public abstract TraceScope newScope(String description, SpanId parentId);

  public static Span getCurrentSpan() {
    return null;
  }

  public abstract void close();

  public abstract TraceScope newScope(String getDelegationToken);
}
