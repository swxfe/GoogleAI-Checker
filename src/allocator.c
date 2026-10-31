#include <mimalloc.h>

/* Use the allocator's own option enum so changes to its ABI are caught at
 * build time. Releasing pages on free also works while the UI thread sleeps. */
void checker_allocator_configure(void) {
    mi_option_set(mi_option_purge_delay, 0);
    mi_option_set(mi_option_arena_eager_commit, 0);
}
