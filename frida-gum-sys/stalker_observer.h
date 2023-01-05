/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#pragma once

#include "frida-gum.h"

G_BEGIN_DECLS

#define GUM_TYPE_RUST_STALKER_OBSERVER (gum_rust_stalker_observer_get_type())
G_DECLARE_FINAL_TYPE(GumRustStalkerObserver, gum_rust_stalker_observer, GUM,
    RUST_STALKER_OBSERVER, GObject)

typedef struct {
  void *user_data;

  void (*notify_backpatch)(void *user_data, const GumBackpatch * backpatch,
    gsize size);
  void (*switch_callback)(void *user_data, gpointer from_address,
    gpointer start_address, gpointer from_insn, gpointer * target);
} RustStalkerObserverVTable;

struct _GumRustStalkerObserver {
  GObject parent;
  RustStalkerObserverVTable rust;
};

GumStalkerObserver *gum_rust_stalker_observer_new(RustStalkerObserverVTable rust);
void gum_rust_stalker_observer_reset(GumRustStalkerObserver *self);

G_END_DECLS
