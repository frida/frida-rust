/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "event_sink.h"

static void gum_rust_event_sink_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(GumRustEventSink,
                       gum_rust_event_sink,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_EVENT_SINK,
                                             gum_rust_event_sink_iface_init))

static void
gum_rust_event_sink_finalize(GObject *obj)
{
  G_OBJECT_CLASS(gum_rust_event_sink_parent_class)->finalize(obj);
}

static void
gum_rust_event_sink_class_init (GumRustEventSinkClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_rust_event_sink_finalize;
}

static GumEventType
gum_rust_event_sink_query_mask(GumEventSink *sink)
{
  GumRustEventSink *self = GUM_RUST_EVENT_SINK (sink);
  return self->rust.query_mask(self->rust.user_data);
}

static void
gum_rust_event_sink_start(GumEventSink *sink)
{
  GumRustEventSink *self = GUM_RUST_EVENT_SINK(sink);
  return self->rust.start(self->rust.user_data);
}

static void
gum_rust_event_sink_process(GumEventSink *sink, const GumEvent *event, GumCpuContext *context)
{
  (void) context;
  GumRustEventSink *self = GUM_RUST_EVENT_SINK(sink);
  return self->rust.process(self->rust.user_data, event);
}

static void
gum_rust_event_sink_flush(GumEventSink *sink)
{
  GumRustEventSink *self = GUM_RUST_EVENT_SINK(sink);
  return self->rust.flush(self->rust.user_data);
}

static void
gum_rust_event_sink_stop(GumEventSink *sink)
{
  GumRustEventSink *self = GUM_RUST_EVENT_SINK(sink);
  return self->rust.stop(self->rust.user_data);
}

static void
gum_rust_event_sink_iface_init(gpointer g_iface, gpointer iface_data)
{
  (void) iface_data;

  GumEventSinkInterface *iface = g_iface;
  iface->query_mask = gum_rust_event_sink_query_mask;
  iface->start = gum_rust_event_sink_start;
  iface->process = gum_rust_event_sink_process;
  iface->flush = gum_rust_event_sink_flush;
  iface->stop = gum_rust_event_sink_stop;
}

static void
gum_rust_event_sink_init(GumRustEventSink *self)
{
  (void) self;
}

GumEventSink*
gum_rust_event_sink_new (RustEventSinkVTable rust)
{
  GumRustEventSink *sink;
  sink = g_object_new(GUM_TYPE_RUST_EVENT_SINK, NULL);
  memcpy(&sink->rust, &rust, sizeof(sink->rust));
  return GUM_EVENT_SINK(sink);
}

void
gum_rust_event_sink_reset(GumRustEventSink *self)
{
  (void) self;
}
