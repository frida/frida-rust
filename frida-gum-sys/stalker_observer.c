/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker_observer.h"

static void gum_rust_stalker_observer_iface_init(gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(GumRustStalkerObserver,
                       gum_rust_stalker_observer,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_OBSERVER,
                                             gum_rust_stalker_observer_iface_init))

static void
gum_rust_stalker_observer_finalize(GObject *obj)
{
  G_OBJECT_CLASS(gum_rust_stalker_observer_parent_class)->finalize(obj);
}

static void
gum_rust_stalker_observer_class_init (GumRustStalkerObserverClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_rust_stalker_observer_finalize;
}

static void
gum_rust_stalker_observer_notify_backpatch(GumStalkerObserver *sink,
    const GumBackpatch * backpatch, gsize size)
{
  GumRustStalkerObserver *self = GUM_RUST_STALKER_OBSERVER(sink);
  return self->rust.notify_backpatch(self->rust.user_data, backpatch, size);
}

static void
gum_rust_stalker_observer_switch_callback(GumStalkerObserver *sink,
    gpointer from_address, gpointer start_address, gpointer from_insn,
    gpointer * target)
{
  GumRustStalkerObserver *self = GUM_RUST_STALKER_OBSERVER(sink);
  return self->rust.switch_callback(self->rust.user_data, from_address,
      start_address, from_insn, target);
}

static void
gum_rust_stalker_observer_iface_init(gpointer g_iface, gpointer iface_data)
{
  (void) iface_data;

  GumStalkerObserverInterface *iface = g_iface;
  iface->notify_backpatch = gum_rust_stalker_observer_notify_backpatch;
  iface->switch_callback = gum_rust_stalker_observer_switch_callback;
}

static void
gum_rust_stalker_observer_init(GumRustStalkerObserver *self)
{
  (void) self;
}

GumStalkerObserver*
gum_rust_stalker_observer_new (RustStalkerObserverVTable rust)
{
  GumRustStalkerObserver *sink;
  sink = g_object_new(GUM_TYPE_RUST_STALKER_OBSERVER, NULL);
  memcpy(&sink->rust, &rust, sizeof(sink->rust));
  return GUM_STALKER_OBSERVER(sink);
}

void
gum_rust_stalker_observer_reset(GumRustStalkerObserver *self)
{
  (void) self;
}
