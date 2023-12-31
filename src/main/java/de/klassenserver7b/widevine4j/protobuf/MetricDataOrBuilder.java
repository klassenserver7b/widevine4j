// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wv_proto2.proto

package de.klassenserver7b.widevine4j.protobuf;

public interface MetricDataOrBuilder extends
    // @@protoc_insertion_point(interface_extends:MetricData)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * 'stage' that is currently processing the SignedMessage.  Required.
   * </pre>
   *
   * <code>optional string stage_name = 1;</code>
   * @return Whether the stageName field is set.
   */
  boolean hasStageName();
  /**
   * <pre>
   * 'stage' that is currently processing the SignedMessage.  Required.
   * </pre>
   *
   * <code>optional string stage_name = 1;</code>
   * @return The stageName.
   */
  java.lang.String getStageName();
  /**
   * <pre>
   * 'stage' that is currently processing the SignedMessage.  Required.
   * </pre>
   *
   * <code>optional string stage_name = 1;</code>
   * @return The bytes for stageName.
   */
  com.google.protobuf.ByteString
      getStageNameBytes();

  /**
   * <pre>
   * metric and associated value.
   * </pre>
   *
   * <code>repeated .MetricData.TypeValue metric_data = 2;</code>
   */
  java.util.List<de.klassenserver7b.widevine4j.protobuf.MetricData.TypeValue> 
      getMetricDataList();
  /**
   * <pre>
   * metric and associated value.
   * </pre>
   *
   * <code>repeated .MetricData.TypeValue metric_data = 2;</code>
   */
  de.klassenserver7b.widevine4j.protobuf.MetricData.TypeValue getMetricData(int index);
  /**
   * <pre>
   * metric and associated value.
   * </pre>
   *
   * <code>repeated .MetricData.TypeValue metric_data = 2;</code>
   */
  int getMetricDataCount();
  /**
   * <pre>
   * metric and associated value.
   * </pre>
   *
   * <code>repeated .MetricData.TypeValue metric_data = 2;</code>
   */
  java.util.List<? extends de.klassenserver7b.widevine4j.protobuf.MetricData.TypeValueOrBuilder> 
      getMetricDataOrBuilderList();
  /**
   * <pre>
   * metric and associated value.
   * </pre>
   *
   * <code>repeated .MetricData.TypeValue metric_data = 2;</code>
   */
  de.klassenserver7b.widevine4j.protobuf.MetricData.TypeValueOrBuilder getMetricDataOrBuilder(
      int index);
}
