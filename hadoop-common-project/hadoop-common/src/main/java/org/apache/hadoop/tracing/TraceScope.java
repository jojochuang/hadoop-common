package org.apache.hadoop.tracing;

public interface TraceScope extends AutoCloseable {
  public void close();

  void addKVAnnotation(String path, String path1);
}
