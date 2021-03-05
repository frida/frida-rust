#pragma once

#include "frida-gum.h"

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
