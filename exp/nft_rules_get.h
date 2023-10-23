#pragma once
#include <libmnl/libmnl.h>
#include <stdint.h>

void dump_rule(const char *table, const char *chain, const uint32_t family,
               mnl_cb_t callback, void *cb_data);
