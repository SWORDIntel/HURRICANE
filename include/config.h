/*
 * Configuration file parser
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "v6gw.h"

/* Parse configuration file */
int config_parse(const char *filename, config_t *config);

/* Validate configuration */
int config_validate(const config_t *config);

/* Print configuration (for debugging) */
void config_print(const config_t *config);

#endif /* CONFIG_H */
