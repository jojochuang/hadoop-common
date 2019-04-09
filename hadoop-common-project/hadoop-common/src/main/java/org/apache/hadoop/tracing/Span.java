package org.apache.hadoop.tracing;

public interface Span {
  public void addKVAnnotation(String key, String value);
}
