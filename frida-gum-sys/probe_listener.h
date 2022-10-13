/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#pragma once

#include "frida-gum.h"

G_BEGIN_DECLS

#define GUM_TYPE_RUST_PROBE_LISTENER (gum_rust_probe_listener_get_type())
G_DECLARE_FINAL_TYPE(GumRustProbeListener, gum_rust_probe_listener, GUM,
    RUST_PROBE_LISTENER, GObject)

typedef struct {
  void *user_data;

  void (*on_hit)(void *user_data, GumInvocationContext *context);
} RustProbeListenerVTable;

struct _GumRustProbeListener {
  GObject parent;
  RustProbeListenerVTable rust;
};

GumInvocationListener *gum_rust_probe_listener_new(RustProbeListenerVTable rust);
void gum_rust_probe_listener_reset(GumRustProbeListener *self);

G_END_DECLS
