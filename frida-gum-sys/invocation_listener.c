/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "invocation_listener.h"

static void gum_rust_invocation_listener_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(GumRustInvocationListener,
                       gum_rust_invocation_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             gum_rust_invocation_listener_iface_init))

static void
gum_rust_invocation_listener_finalize (GObject *obj)
{
  G_OBJECT_CLASS(gum_rust_invocation_listener_parent_class)->finalize(obj);
}

static void
gum_rust_invocation_listener_class_init(GumRustInvocationListenerClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_rust_invocation_listener_finalize;
}

static void
gum_rust_invocation_listener_on_enter(GumInvocationListener *listener, GumInvocationContext *context)
{
  GumRustInvocationListener *self = GUM_RUST_INVOCATION_LISTENER(listener);
  return self->rust.on_enter(self->rust.user_data, context);
}

static void
gum_rust_invocation_listener_on_leave(GumInvocationListener *listener, GumInvocationContext *context)
{
  GumRustInvocationListener *self = GUM_RUST_INVOCATION_LISTENER(listener);
  return self->rust.on_leave(self->rust.user_data, context);
}

static void
gum_rust_invocation_listener_iface_init(gpointer g_iface, gpointer iface_data)
{
  (void) iface_data;

  GumInvocationListenerInterface *iface = g_iface;
  iface->on_enter = gum_rust_invocation_listener_on_enter;
  iface->on_leave = gum_rust_invocation_listener_on_leave;
}

static void
gum_rust_invocation_listener_init(GumRustInvocationListener *self)
{
  (void) self;
}

GumInvocationListener*
gum_rust_invocation_listener_new(RustInvocationListenerVTable rust)
{
  GumRustInvocationListener *listener;
  listener = g_object_new(GUM_TYPE_RUST_INVOCATION_LISTENER, NULL);
  memcpy(&listener->rust, &rust, sizeof(listener->rust));
  return GUM_INVOCATION_LISTENER(listener);
}

void
gum_rust_invocation_listener_reset(GumRustInvocationListener *self)
{
  (void) self;
}
