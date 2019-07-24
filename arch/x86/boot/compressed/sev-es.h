#ifndef __SEV_ES_H
#define __SEV_ES_H

#ifdef CONFIG_AMD_SEV_ES_GUEST
void reset_ghcb(void);
#else
#define reset_ghcb()
#endif

#endif
