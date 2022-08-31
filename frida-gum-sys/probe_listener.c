/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "probe_listener.h"

static void gum_rust_probe_listener_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(GumRustProbeListener,
                       gum_rust_probe_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             gum_rust_probe_listener_iface_init))

static void
gum_rust_probe_listener_finalize (GObject *obj)
{
  G_OBJECT_CLASS(gum_rust_probe_listener_parent_class)->finalize(obj);
}

static void
gum_rust_probe_listener_class_init(GumRustProbeListenerClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_rust_probe_listener_finalize;
}

static void
gum_rust_probe_listener_callback(GumInvocationListener *listener, GumInvocationContext *context)
{
  GumRustProbeListener *self = GUM_RUST_PROBE_LISTENER(listener);
  return self->rust.on_hit(self->rust.user_data, context);
}

static void
gum_rust_probe_listener_iface_init(gpointer g_iface, gpointer iface_data)
{
  (void) iface_data;

  GumInvocationListenerInterface *iface = g_iface;
  iface->on_enter = gum_rust_probe_listener_callback;
  iface->on_leave = NULL;
}

static void
gum_rust_probe_listener_init(GumRustProbeListener *self)
{
  (void) self;
}

GumInvocationListener*
gum_rust_probe_listener_new(RustProbeListenerVTable rust)
{
  GumRustProbeListener *listener;
  listener = g_object_new(GUM_TYPE_RUST_PROBE_LISTENER, NULL);
  memcpy(&listener->rust, &rust, sizeof(listener->rust));
  return GUM_INVOCATION_LISTENER(listener);
}

void
gum_rust_probe_listener_reset(GumRustProbeListener *self)
{
  (void) self;
}
