#include <stdlib.h>
#include "ofmt.h"
#include "output/outlib.h"
#include "output/outform.h"

static void dummy_init(void)
{
}

static int dummy_setinfo(enum geninfo type, char **string)
{
    return 0; // not recognized
}

static void dummy_output(int32_t segto, const void *_data, 
                   enum out_type type, uint64_t size, 
                   int32_t segment, int32_t wrt)
{
#if 0
    const uint8_t*data = _data;
    uint64_t i;
    for(i=0;i<size;i++) {
	printf("%02x ", data[i]);
        if((i&7) == 7 || i == size-1)
            printf("\n");
    }
#endif
}

static void dummy_symdef(char *name, int32_t segment, int64_t offset,
                   int is_global, char *special)
{
}

static int32_t dummy_section(char *name, int pass, int *bits)
{
    return 0xaaaaffff;
}

static void dummy_sectalign(int32_t seg, unsigned int value)
{
}

static int32_t dummy_segbase(int32_t segment)
{
    return segment;
    return NO_SEG;
}

static int dummy_directive(enum directives directive, char *value, int pass)
{
    return 0; // not recognized
}

static void dummy_filename(char *inname, char *outname)
{
}

static void dummy_cleanup(int debuginfo)
{
}

struct ofmt dummy_ofmt = {
    "dummy",
    "dummy",
    0,
    null_debug_arr,
    &null_debug_form,
    NULL,
    dummy_init,
    dummy_setinfo,
    dummy_output,
    dummy_symdef,
    dummy_section,
    dummy_sectalign,
    dummy_segbase,
    dummy_directive,
    dummy_filename,
    dummy_cleanup
};

struct ofmt * dummy_ofmt_new()
{
    struct ofmt * o = malloc(sizeof(struct ofmt));
    *o = dummy_ofmt;
    return o;
}

