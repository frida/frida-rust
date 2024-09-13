#pragma once

#if USE_GUM_JS == 1
# include "frida-gumjs.h"
#else
# include "frida-gum.h"
#endif

G_BEGIN_DECLS

#if defined (_M_ARM64) || defined (__aarch64__)
GumStalker * gum_stalker_new_with_params (guint stalker_ic_entries);
#elif defined (__x86_64__)
GumStalker * gum_stalker_new_with_params (guint stalker_ic_entries, guint stalker_adjacent_blocks);
#endif

G_END_DECLS
