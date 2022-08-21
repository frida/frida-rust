/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#pragma once

#include "frida-gum.h"

G_BEGIN_DECLS

#define GUM_TYPE_RUST_INSTRUCTION_INVOCATION_LISTENER (gum_rust_instruction_invocation_listener_get_type())
G_DECLARE_FINAL_TYPE(GumRustInstructionInvocationListener, gum_rust_instruction_invocation_listener, GUM,
    RUST_INSTRUCTION_INVOCATION_LISTENER, GObject)

typedef struct {
  void *user_data;

  void (*callback)(void *user_data, GumInvocationContext *context);
} RustInstructionInvocationListenerVTable;

struct _GumRustInstructionInvocationListener {
  GObject parent;
  RustInstructionInvocationListenerVTable rust;
};

GumInvocationListener *gum_rust_instruction_invocation_listener_new(RustInstructionInvocationListenerVTable rust);
void gum_rust_instruction_invocation_listener_reset(GumRustInstructionInvocationListener *self);

G_END_DECLS
