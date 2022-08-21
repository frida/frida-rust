/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "instruction_invocation_listener.h"

static void gum_rust_instruction_invocation_listener_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(GumRustInstructionInvocationListener,
                       gum_rust_instruction_invocation_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             gum_rust_instruction_invocation_listener_iface_init))

static void
gum_rust_instruction_invocation_listener_finalize (GObject *obj)
{
  G_OBJECT_CLASS(gum_rust_instruction_invocation_listener_parent_class)->finalize(obj);
}

static void
gum_rust_instruction_invocation_listener_class_init(GumRustInstructionInvocationListenerClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_rust_instruction_invocation_listener_finalize;
}

static void
gum_rust_instruction_invocation_listener_callback(GumInvocationListener *listener, GumInvocationContext *context)
{
  GumRustInstructionInvocationListener *self = GUM_RUST_INSTRUCTION_INVOCATION_LISTENER(listener);
  return self->rust.callback(self->rust.user_data, context);
}

static void
gum_rust_instruction_invocation_listener_iface_init(gpointer g_iface, gpointer iface_data)
{
  (void) iface_data;

  GumInvocationListenerInterface *iface = g_iface;
  iface->on_enter = gum_rust_instruction_invocation_listener_callback;
  iface->on_leave = NULL;
}

static void
gum_rust_instruction_invocation_listener_init(GumRustInstructionInvocationListener *self)
{
  (void) self;
}

GumInvocationListener*
gum_rust_instruction_invocation_listener_new(RustInstructionInvocationListenerVTable rust)
{
  GumRustInstructionInvocationListener *listener;
  listener = g_object_new(GUM_TYPE_RUST_INSTRUCTION_INVOCATION_LISTENER, NULL);
  memcpy(&listener->rust, &rust, sizeof(listener->rust));
  return GUM_INVOCATION_LISTENER(listener);
}

void
gum_rust_instruction_invocation_listener_reset(GumRustInstructionInvocationListener *self)
{
  (void) self;
}
