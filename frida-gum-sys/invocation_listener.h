/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#pragma once

#if USE_GUM_JS == 1
# include "frida-gumjs.h"
#else
# include "frida-gum.h"
#endif

G_BEGIN_DECLS

#define GUM_TYPE_RUST_INVOCATION_LISTENER (gum_rust_invocation_listener_get_type())
G_DECLARE_FINAL_TYPE(GumRustInvocationListener, gum_rust_invocation_listener, GUM,
    RUST_INVOCATION_LISTENER, GObject)

typedef struct {
  void *user_data;

  void (*on_enter)(void *user_data, GumInvocationContext *context);
  void (*on_leave)(void *user_data, GumInvocationContext *context);
} RustInvocationListenerVTable;

struct _GumRustInvocationListener {
  GObject parent;
  RustInvocationListenerVTable rust;
};

GumInvocationListener *gum_rust_invocation_listener_new(RustInvocationListenerVTable rust);
void gum_rust_invocation_listener_reset(GumRustInvocationListener *self);

G_END_DECLS
