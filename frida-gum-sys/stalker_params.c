#include "stalker_params.h"

#if defined (_M_ARM64) || defined (__aarch64__)
GumStalker *
gum_stalker_new_with_params (guint stalker_ic_entries)
{
  GumStalker * stalker = g_object_new(GUM_TYPE_STALKER, "ic-entries",
    stalker_ic_entries, NULL);
  return stalker;
}
#elif defined (_M_IX86) || defined (__i386__) || defined (_M_X64) || defined (__x86_64__)
GumStalker *
gum_stalker_new_with_params (guint stalker_ic_entries, guint stalker_adjacent_blocks)
{
  GumStalker * stalker = g_object_new(GUM_TYPE_STALKER, "ic-entries",
    stalker_ic_entries, "adjacent-blocks", stalker_adjacent_blocks, NULL);
  return stalker;
}
#endif
