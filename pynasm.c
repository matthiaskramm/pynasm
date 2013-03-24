/* pynasm.c

   Python wrapper for the nasm assembler.

   Copyright (c) 2013 Matthias Kramm <matthias@quiss.org>
 
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/* python includes */
#define _SYS_UCONTEXT_H
#include <Python.h>
#include <stdarg.h>

/* nasm includes */
#include "nasm.h"
#include "nasmlib.h"
#include "saa.h"
#include "raa.h"
#include "float.h"
#include "stdscan.h"
#include "insns.h"
#include "preproc.h"
#include "parser.h"
#include "eval.h"
#include "assemble.h"
#include "labels.h"
#include "listing.h"
#include "tables.h"
#include "insnsi.h"

/* local includes */
#include "ofmt.h"

/* for call() */
#include <sys/mman.h>

typedef struct _state {
    int dummy;
} state_t;

#if PY_MAJOR_VERSION >= 3
#define PYTHON23_HEAD_INIT \
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
#define M_FLAGS (METH_VARARGS|METH_KEYWORDS)
#define STATE(m) ((state_t*)PyModule_GetState(m))
#else
#define PYTHON23_HEAD_INIT \
    PyObject_HEAD_INIT(NULL) \
    0,
#define M_FLAGS (METH_KEYWORDS)
static state_t _python2_module_state = {0};
#define STATE(m) (&_python2_module_state)
#endif

static PyTypeObject CodeClass;
static PyTypeObject OpcodeClass;
static PyTypeObject RegisterClass;
static PyTypeObject RegisterExpressionClass;
static PyTypeObject LabelClass;
static PyTypeObject InstructionClass;

typedef int int_function();

typedef struct {
    PyObject_HEAD
    struct location location;
    int num_bits;
    uint32_t cpu;

    PyObject*instructions;

    PyObject*data;
    int64_t size;

    int_function*function; // filled in after code_finish()
} CodeObject;

typedef struct {
    PyObject_HEAD
    insn ins;
    uint64_t size;
    const char*label;
} InstructionObject;

typedef struct {
    PyObject_HEAD
    const char*name;
    enum opcode opcode;
    enum ccode condition;
} OpcodeObject;

typedef struct {
    PyObject_HEAD
    const char*name;

    enum reg_enum reg;
    opflags_t reg_flags;
} RegisterObject;

typedef struct {
    PyObject_HEAD
    const char*name;
} LabelObject;

#define HAS_BASE  1
#define HAS_INDEX 2
#define HAS_OFFSET 4
typedef struct {
    PyObject_HEAD
    const char*name;

    uint8_t flags;
    enum reg_enum base_reg;
    enum reg_enum index_reg;
    int scale;
    int64_t offset;
} RegisterExpressionObject;

/* XXX During code generation, we have one global current execution frame.
       This means that we don't support code generation in multiple threads,
       or, for that matter, interleaved code generation.

       Notice that to lift this restriction, we would also need to modify nasm, 
       which has a lot of global variables, as well as global error handling.
*/
static struct global_state {
    CodeObject* current_code;
    const char* last_error;

    /* We keep track of which threads to access to global state to warn the
       user if we see any concurrency issues. 
       FIXME: This needs more locking. */
    PyThreadState* current_code_thread;
} global_state;

struct ofmt* pynasm_ofmt;

static char* strf(char*format, ...)
{
    char buf[1024];
    int l;
    va_list arglist;
    va_start(arglist, format);
    vsnprintf(buf, sizeof(buf)-1, format, arglist);
    va_end(arglist);
    return strdup(buf);
}

static inline PyObject*pystring_fromstring(const char*s)
{
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(s);
#else
    return PyString_FromString(s);
#endif
}
static inline int pystring_check(PyObject*o)
{
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_Check(o);
#else
    return PyString_Check(o);
#endif
}
static inline PyObject*pyint_fromlong(long l)
{
#if PY_MAJOR_VERSION >= 3
    return PyLong_FromLong(l);
#else
    return PyInt_FromLong(l);
#endif
}
static inline const char*pystring_asstring(PyObject*s)
{
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_AS_DATA(s);
#else
    return PyString_AsString(s);
#endif
}
PyObject*forward_getattr(PyObject*self, char *a)
{
    PyObject*o = pystring_fromstring(a);
    PyObject*ret = PyObject_GenericGetAttr(self, o);
    Py_DECREF(o);
    return ret;
}

#define PY_ERROR_F(s,args...) (PyErr_SetString(PyExc_Exception, strf(s, ## args)), (void*)NULL)
#define PY_ERROR(s) (PyErr_SetString(PyExc_Exception, s), (void*)NULL)
#define PY_NONE Py_BuildValue("s", 0)

// -----------------------------------------------------------------------------

static void pynasm_error(int severity, const char *fmt, ...)
{
    static char buf[1024];
    int l;
    va_list arglist;
    if(severity < -1000)
        return;
    va_start(arglist, fmt);
    vsnprintf(buf, sizeof(buf)-1, fmt, arglist);
    va_end(arglist);
    l = strlen(buf);
    while(l && buf[l-1]=='\n') {
	buf[l-1] = 0;
	l--;
    }
    //printf("(pynasm) %s\n", buf);
    //fflush(stdout);
    global_state.last_error = buf;
}

static void code_add_data(CodeObject* self, const void*data, uint64_t length);

static void pynasm_output(int32_t segto, const void *data, 
                          enum out_type type, uint64_t size, 
                          int32_t segment, int32_t wrt)
{
    code_add_data(global_state.current_code, data, size);
}

// -----------------------------------------------------------------------------

PyDoc_STRVAR(code_new_doc,
"Create a new empty assembly function\n"
);

static PyObject* code_new(PyObject* module, PyObject* args, PyObject* kwargs)
{
    static char *kwlist[] = {"input", "output", NULL};
    PyObject*input = NULL;
    PyObject*output = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OO", kwlist, &input, &output)) {
	return NULL;
    }

    CodeObject*self = PyObject_New(CodeObject, &CodeClass);
    self->num_bits = 32;
    self->location.segment = pynasm_ofmt->section(NULL, 0, &self->num_bits);
    self->location.offset = 0;
    self->cpu = IF_PLEVEL; // maximum level
#if PY_MAJOR_VERSION >= 3
    self->data = PyByteArray_FromStringAndSize("", 0);
#else
    self->data = PyString_FromStringAndSize("", 0);
#endif
    self->instructions = PyList_New(0);
    self->size = 0;
    return (PyObject*)self;
}

static PyObject* code__enter__(PyObject* _self, PyObject* args, PyObject* kwargs)
{
    CodeObject*self = (CodeObject*)_self;
    static char *kwlist[] = {NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwlist)) {
	return NULL;
    }
    if(global_state.current_code) {
        if(global_state.current_code_thread != PyThreadState_GET()) {
            return PY_ERROR("Multithreaded code generation not supported");
        }
        return PY_ERROR("You can't nest two assembly with-statements");
    }

    Py_INCREF(self);
    global_state.current_code = self;
    global_state.current_code_thread = PyThreadState_GET();

    Py_INCREF(self);
    return (PyObject*)self;
}

static void code_add_data(CodeObject* self, const void*data, uint64_t length) 
{
#if PY_MAJOR_VERSION >= 3
    Py_ssize_t pos = PyByteArray_GET_SIZE(self->data);
    PyByteArray_Resize(self->data, pos + length);
    memcpy(((PyByteArrayObject*)self->data)->ob_bytes + pos, data, length);
#else
    /* _PyStringObject_Resize assumes that the ref cnt of a string is 1,
       but there's no easy way to initialize  an empty string that is
       not interned (and the interned empty string has a very high ref
       count), so we have to do things in a less efficient way */
    PyObject*append = PyString_FromStringAndSize(data, length);
    PyString_Concat(&self->data, append);
#endif
    self->size += length;
}

static int code_append_instruction(CodeObject* self, InstructionObject*ins)
{
    if(PyList_Append((PyObject*)self->instructions, (PyObject*)ins) < 0) {
        return -1;
    }
    return 0;
}

void code_add_ret(CodeObject*self)
{
    uint8_t ret = 0xc3;
    code_add_data(self, &ret, 1);
}

static int backpatch(struct location*location, insn*ins, const char*label);

static int code_emit_instructions(CodeObject*code)
{
    int num = PyList_Size(code->instructions);
    int i;

    code->location.offset = 0;
    for(i=0;i<num;i++) {
        InstructionObject*instruction = (InstructionObject*)PyList_GET_ITEM(code->instructions, i);
        if(instruction->ob_type != &InstructionClass) {
            PY_ERROR("internal error: non-instructions in instruction stream");
            return -1;
        }
        if(instruction->label) {
            int ret = backpatch(&code->location, &instruction->ins, instruction->label);
            if(ret<0)
                return -1;
        }

        /* this will call pynasm_output via callback */
        int64_t size = assemble(code->location.segment,
                                code->location.offset,
                                code->num_bits,
                                code->cpu,
                                &instruction->ins,
                                pynasm_ofmt,
                                pynasm_error,
                                &nasmlist);

        if(global_state.last_error) {
            PyErr_SetString(PyExc_Exception, global_state.last_error);
            global_state.last_error = NULL;
            return -1;
        }

        if(size != instruction->size) {
            PY_ERROR("Internal error: operand size mismatch between first and second pass");
            return -1;
        }

        code->location.offset += size;
        if(code->location.offset != code->size) {
            PY_ERROR("Internal error: lost track of position in stream");
            return -1;
        }
    }
    return 0;
}

static PyObject* code_finish(CodeObject*self)
{
    if(code_emit_instructions(self) < 0) {
        return NULL;
    }
    code_add_ret(self);

    union {
        ptrdiff_t addr;
        void*data;
        int_function*f;
    } ptr;

#if PY_MAJOR_VERSION >= 3
    ptr.data = ((PyByteArrayObject*)self->data)->ob_bytes;
    size_t size = PyByteArray_GET_SIZE(self->data);
#else
    ptr.data = ((PyStringObject*)self->data)->ob_sval;
    size_t size = PyString_GET_SIZE(self->data);
#endif

    if(mprotect((void *)(ptr.addr & 0xFFFFF000), size + (ptr.addr & 0xFFF),
            PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        PyErr_SetFromErrno(PY_NONE);
        return NULL;
    }
    self->function = ptr.f;
    return PY_NONE;
}

static PyObject* code__exit__(PyObject* self, PyObject* args, PyObject* kwargs)
{
    PyObject*exc_type = NULL;
    PyObject*exc_value = NULL;
    PyObject*exc_traceback = NULL;
    if (!PyArg_ParseTuple(args, "OOO", &exc_type, &exc_value, &exc_traceback)) {
        fprintf(stderr, "Internal error in parsing arguments to pynasm __exit__ call");
	return NULL;
    }
    if(exc_type != Py_None ||
       exc_value != Py_None ||
       exc_traceback != Py_None) {
        Py_DECREF(self);
        global_state.current_code = NULL; 
        return PY_NONE; // do not swallow exception
    }

    /* make code callable */
    PyObject*result = code_finish(global_state.current_code);

    Py_DECREF(self);
    global_state.current_code = NULL; 
    return result;
}

static void code_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static PyObject* code_getattr(PyObject * _self, char* a)
{
    CodeObject*self = (CodeObject*)_self;
    if(!strcmp(a, "bytes")) {
        Py_INCREF(self->data);
        return self->data;
    }
    return forward_getattr(_self, a);
}

static int code_print(PyObject * _self, FILE *fi, int flags)
{
    CodeObject*self = (CodeObject*)_self;
    fprintf(fi, "<code object at %p(%d)>", _self, _self?_self->ob_refcnt:0);
    return 0;
}

static PyMethodDef code_exit_methoddef = {"__exit__", (PyCFunction)code__exit__, M_FLAGS, NULL};
static PyMethodDef code_enter_methoddef = {"__enter__", (PyCFunction)code__enter__, M_FLAGS, NULL};

PyDoc_STRVAR(code_add_instruction_doc,
"add_instruction(name, operands)\n\n"
"Adds a single assembly instruction to this function.\n"
);

PyObject * code_call(PyObject* _self, PyObject *args, PyObject *kwargs)
{
    CodeObject*self = (CodeObject*)_self;
    int ret = self->function();
    Py_INCREF(Py_None);
    return pyint_fromlong(ret);
}

PyDoc_STRVAR(code_doc,
"A code object stores an executable assembly program.\n"
);

static PyObject* code_descr_get(PyObject *res, PyObject *self, PyObject *type)
{
    printf("%s\n", res->ob_type->tp_name);
    return res;
}
/*
    if((f = Py_TYPE(res)->tp_descr_get) == NULL)
        Py_INCREF(res);
    else
        res = f(res, self, (PyObject *)(Py_TYPE(self)));
*/

static PyObject* code_tp_dict()
{   
    PyObject*tp_dict = PyDict_New();
    PyObject*exit = PyDescr_NewMethod(&CodeClass, &code_exit_methoddef);
    PyObject*enter = PyDescr_NewMethod(&CodeClass, &code_enter_methoddef);
    PyDict_SetItem(tp_dict, pystring_fromstring("__exit__"), exit);
    PyDict_SetItem(tp_dict, pystring_fromstring("__enter__"), enter);
    return tp_dict;
}

static PyMethodDef code_methods[] =
{
    //{"_", (PyCFunction)code_add_instruction, M_FLAGS, code_add_instruction_doc},
    {0,0,0,0}
};

// -----------------------------------------------------------------------------

/* the nasm definition of "opcode" is basically the name of an instruction, 
   without arguments/registers (e.g. "mov".)  */

static void opcode_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static int opcode_print(PyObject * _self, FILE *fi, int flags)
{
    OpcodeObject*self = (OpcodeObject*)_self;
    
    fprintf(fi, "<opcode object at %p(%d)>", _self, _self?_self->ob_refcnt:0);
    return 0;
}

static int parse_operands(PyObject*args, struct location* location, insn* ins, const char**_label)
{
    int l = PyTuple_GET_SIZE(args);
    if(l > MAX_OPERANDS) {
        PyErr_SetString(PyExc_Exception, "too many parameters");
        return -1;
    }
    ins->operands = l;

    int i;
    for(i=0;i<l;i++) {
        PyObject*o = PyTuple_GET_ITEM(args, i);
        if(o->ob_type == &RegisterClass) {
            RegisterObject*r = (RegisterObject*)o;
            ins->oprs[i].type = r->reg_flags;
            ins->oprs[i].basereg = r->reg;
        } else if(PyLong_Check(o)) {
            ins->oprs[i].type = IMMEDIATE;
            ins->oprs[i].basereg = R_none;
            ins->oprs[i].indexreg = R_none;
            ins->oprs[i].offset = PyLong_AsLongLong(o);
#if PY_MAJOR_VERSION < 3
        } else if(PyInt_Check(o)) {
            ins->oprs[i].type = IMMEDIATE;
            ins->oprs[i].basereg = R_none;
            ins->oprs[i].indexreg = R_none;
            ins->oprs[i].offset = PyInt_AsLong(o);
#endif
        } else if(PyList_Check(o)) {
            if(PyList_Size(o) != 1) {
                PyErr_SetString(PyExc_Exception, "invalid [] syntax");
                return -1;
            }
            PyObject* e = PyList_GetItem(o, 0);
            if(e->ob_type == &RegisterClass) {
                RegisterObject*r = (RegisterObject*)e;
                ins->oprs[i].type = MEMORY;
                ins->oprs[i].basereg = r->reg;
                ins->oprs[i].indexreg = R_none;
            } else if(e->ob_type == &RegisterExpressionClass) {
                /* FIXME: this creates an offset, even if offset is 0 */
                RegisterExpressionObject*r = (RegisterExpressionObject*)e;
                ins->oprs[i].type = MEMORY;
                ins->oprs[i].basereg = r->base_reg;
                ins->oprs[i].indexreg = r->index_reg;
                ins->oprs[i].scale = r->scale;
                ins->oprs[i].offset = r->offset;
                ins->oprs[i].segment = NO_SEG;
                //do this to force the mod bits to be > 0 (add an offset):
                //ins.oprs[i].eaflags = EAF_BYTEOFFS;
            } else {
                PyErr_SetString(PyExc_Exception, "invalid operand in [...]");
                return -1;
            }
        } else if(pystring_check(o)) {
            const char*label = pystring_asstring(o);
            *_label = label;
            ins->forw_ref = true;
            ins->oprs[i].type = IMMEDIATE|NEAR;
            ins->oprs[i].basereg = R_none;
            ins->oprs[i].indexreg = R_none;
            ins->oprs[i].offset = 0;
            ins->oprs[i].eaflags = EAF_REL;
        } else {
            PyErr_SetString(PyExc_Exception, "invalid operand");
            return -1;
        }
    }
}

static int backpatch(struct location*location, insn*ins, const char*label)
{
    int32_t segment;
    int64_t offset = 0;
    if(!lookup_label((char*)label, &segment, &offset)) {
        PY_ERROR_F("could't find label %s", label);
        return -1;
    }
    if(segment != location->segment) {
        PY_ERROR_F("Label %s points to a label in a different code segment", label);
        return -1;
    }
    ins->forw_ref = false;
    ins->oprs[0].offset = offset - location->offset - 2;
    return 0;
}

static PyObject* opcode_call(PyObject* _self, PyObject* args, PyObject* kwargs)
{
    OpcodeObject*self = (OpcodeObject*)_self;
    if(kwargs && PyDict_Size(kwargs)) 
        return PY_ERROR("opcodes don't support keyword arguments");

    if(!global_state.current_code) {
        return PY_ERROR("not within a code frame (use \"with nasm.function(): ...\" to create one)");
    }

    CodeObject*code = global_state.current_code;

    const char*label = NULL;
    insn ins;
    memset(&ins, 0, sizeof(ins));
    ins.times = 1;
    ins.opcode = self->opcode;
    ins.condition = self->condition;

    if(parse_operands(args, &code->location, &ins, &label)<0)
        return NULL;

    int64_t size = insn_size(code->location.segment, 
                             code->location.offset, 
                             code->num_bits, 
                             code->cpu, 
                             &ins, 
                             pynasm_error);

    if(global_state.last_error) {
        // pass 1 error
        PyErr_SetString(PyExc_Exception, global_state.last_error);
        global_state.last_error = NULL;
        return NULL;
    }

    InstructionObject*instruction = PyObject_New(InstructionObject, &InstructionClass);
    instruction->ins = ins;
    instruction->label = label;
    instruction->size = size;

    if(code_append_instruction(code, instruction) < 0)
        return NULL;

    code->location.offset += size;

    return (PyObject*)instruction;
}

PyDoc_STRVAR(opcode_doc,
"Can be called to append this opcode to the current frame.\n"
);

static PyMethodDef opcode_methods[] =
{
    {0,0,0,0}
};

// -----------------------------------------------------------------------------
static void register_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static int register_print(PyObject * _self, FILE *fi, int flags)
{
    RegisterObject*self = (RegisterObject*)_self;
    fprintf(fi, "%s", self->name);
    return 0;
} 
static PyObject* register_to_expression(PyObject*o)
{
    RegisterObject*r = (RegisterObject*)o;
    RegisterExpressionObject*e = PyObject_New(RegisterExpressionObject, &RegisterExpressionClass);
    e->flags = HAS_BASE;
    e->base_reg = r->reg;
    e->index_reg = R_none;
    e->scale = 0;
    return (PyObject*)e;
}
static PyObject* register_multiply(PyObject * o1, PyObject * o2) 
{
    PyObject* tmp = NULL;
    if(o1->ob_type == &RegisterClass)
        o1 = tmp = register_to_expression(o1);
    PyObject*result = o1->ob_type->tp_as_number->nb_multiply(o1, o2);
    Py_DecRef(tmp);
    return result;
}

static PyObject* register_add(PyObject * o1, PyObject * o2) 
{
    PyObject* tmp = NULL;
    if(o1->ob_type == &RegisterClass)
        o1 = tmp = register_to_expression(o1);
    PyObject*result = o1->ob_type->tp_as_number->nb_add(o1, o2);
    Py_DecRef(tmp);
    return result;
}

PyDoc_STRVAR(register_doc,
"An assembly register\n"
);

static PyMethodDef register_methods[] =
{
    {0,0,0,0}
};
// -----------------------------------------------------------------------------
static RegisterExpressionObject* register_expression_new()
{
    RegisterExpressionObject*r = PyObject_New(RegisterExpressionObject, &RegisterExpressionClass);
    r->flags = 0;
    r->base_reg = R_none;
    r->index_reg = R_none;
    r->scale = 0;
    r->offset = 0;
    return r;
}
static void register_expression_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static int register_expression_print(PyObject * _self, FILE *fi, int flags)
{
    RegisterExpressionObject*self = (RegisterExpressionObject*)_self;
    fprintf(fi, "[%d %d] %s + %s * %d + %08llx\n", 
            self->index_reg,
            self->base_reg,
            self->index_reg != R_none ? nasm_reg_names[self->index_reg-1] : "<void>",
            self->base_reg != R_none ? nasm_reg_names[self->base_reg-1] : "<void>",
            self->scale,
            self->offset
            );
    return 0;
} 

static PyObject* register_expression_multiply(PyObject * o, PyObject * n) 
{
    if(o->ob_type != &RegisterExpressionClass) {
        return PY_ERROR_F("internal error: %s", o->ob_type->tp_name);
    }
    RegisterExpressionObject*r = (RegisterExpressionObject*)o;
    int scale = 0;
    if(r->flags != HAS_BASE)
        return PY_ERROR("you can only scale registers (and only once)");

#if PY_MAJOR_VERSION < 3
    if(PyInt_Check(n)) {
        scale = PyInt_AsLong(n);
    }
#endif
    if(PyLong_Check(n)) {
        scale = PyLong_AsLongLong(n);
    }
    if(scale == 0) {
        return PY_ERROR("second operand in (reg * n) must be a number");
    }
    RegisterExpressionObject*result = register_expression_new();
    result->flags = HAS_INDEX;
    result->base_reg = R_none;
    result->index_reg = r->base_reg;
    result->scale = scale;
    return (PyObject*)result;
}

static PyObject* register_expression_add(PyObject * o1, PyObject * o2) 
{
    RegisterExpressionObject*r = register_expression_new();
    if(o1->ob_type != &RegisterExpressionClass) {
        return PY_ERROR_F("internal error: %s", o1->ob_type->tp_name);
    }
    PyObject*tmp = NULL;
    if(o2->ob_type == &RegisterClass) {
        o2 = tmp = register_to_expression(o2);
    }
    RegisterExpressionObject*r1 = (RegisterExpressionObject*)o1;
    if(o2->ob_type == &RegisterExpressionClass) {
        RegisterExpressionObject*r2 = (RegisterExpressionObject*)o2;
        if(r1->scale > 1 && r2->scale > 1) {
            Py_DecRef(tmp);
            return PY_ERROR("Cannot scale two or more register_expressions");
        }
        r->flags = HAS_BASE | HAS_INDEX;
        int both_flags = r1->flags | r2->flags;
        if((r1->flags&HAS_BASE) && (r2->flags&HAS_BASE) && !(both_flags&HAS_INDEX)) {
            r->base_reg = r1->base_reg;
            r->index_reg = r2->base_reg;
            r->scale = 1;
        } else if(!(r1->flags&HAS_INDEX) && (r2->flags&HAS_INDEX)) {
            r->base_reg = r1->base_reg;
            r->index_reg = r2->index_reg;
            r->scale = r2->scale;
        } else if((r1->flags&HAS_INDEX) && !(r2->flags&HAS_INDEX)) {
            r->base_reg = r2->base_reg;
            r->index_reg = r1->index_reg;
            r->scale = r1->scale;
        } else {
            Py_DecRef(tmp);
            return PY_ERROR("invalid combination of operands");
        }
#if PY_MAJOR_VERSION < 3
    } else if(PyInt_Check(o2)) {
        r->flags |= HAS_OFFSET;
        r->offset += PyInt_AsLong(o2);
#endif
    } else if(PyLong_Check(o2)) {
        r->flags |= HAS_OFFSET;
        r->offset += PyLong_AsLongLong(o2);
    } else {
        Py_DecRef(tmp);
        return PY_ERROR("invalid operands");
    }
    return (PyObject*)r;
}

PyDoc_STRVAR(register_expression_doc,
"An expression, for use as memory referenc\n"
);

static PyMethodDef register_expression_methods[] =
{
    {0,0,0,0}
};
// -----------------------------------------------------------------------------
PyDoc_STRVAR(label_new_doc,
"Create a new label\n"
);
static PyObject* label_new(PyObject* module, PyObject* args, PyObject* kwargs)
{
    static char *kwlist[] = {"name", NULL};
    char* name = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name)) {
	return NULL;
    }

    LabelObject*self = PyObject_New(LabelObject, &LabelClass);
    self->name = name;

    CodeObject*code = global_state.current_code;
    define_label(name, code->location.segment, code->location.offset, NULL, true, false);
    if(global_state.last_error) {
        PyErr_SetString(PyExc_Exception, global_state.last_error);
        global_state.last_error = NULL;
        return NULL;
    }
    return (PyObject*)self;
}

static void label_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static int label_print(PyObject * _self, FILE *fi, int flags)
{
    LabelObject*self = (LabelObject*)_self;
    fprintf(fi, "%s", self->name);
    return 0;
} 

PyDoc_STRVAR(label_doc,
"A label (e.g. a jump destination)\n"
);

static PyMethodDef label_methods[] =
{
    {0,0,0,0}
};
// -----------------------------------------------------------------------------
static void instruction_dealloc(PyObject* _self) {
    PyObject_Del(_self);
}

static int instruction_print(PyObject * _self, FILE *fi, int flags)
{
    InstructionObject*self = (InstructionObject*)_self;
    fprintf(fi, "<instruction object at %p(%d)>", _self, _self?_self->ob_refcnt:0);
    return 0;
} 

PyDoc_STRVAR(instruction_doc,
"A instruction (opcode + operands)\n"
);

static PyMethodDef instruction_methods[] =
{
    {0,0,0,0}
};
// -----------------------------------------------------------------------------

static PyTypeObject CodeClass =
{
    PYTHON23_HEAD_INIT
    .tp_name = "pynasm.Code",
    .tp_basicsize = sizeof(CodeObject),
    .tp_itemsize = 0,
    .tp_dealloc = code_dealloc,
    .tp_print = code_print,
    .tp_getattr = code_getattr,
    .tp_doc = code_doc,
    .tp_methods = code_methods,
    /* TODO: it might be nicer to only set this after finish() */
    .tp_call = code_call,
};

static PyTypeObject OpcodeClass =
{
    PYTHON23_HEAD_INIT
    .tp_name = "pynasm.Opcode",
    .tp_basicsize = sizeof(OpcodeObject),
    .tp_itemsize = 0,
    .tp_dealloc = opcode_dealloc,
    .tp_print = opcode_print,
    .tp_doc = opcode_doc,
    .tp_methods = opcode_methods,
    .tp_call = opcode_call,
};

static PyNumberMethods register_as_number = {
    .nb_multiply = register_multiply,
    .nb_add = register_add,
};
static PyTypeObject RegisterClass =
{
    PYTHON23_HEAD_INIT
#if PY_MAJOR_VERSION < 3
    .tp_flags = Py_TPFLAGS_CHECKTYPES, // for multiply
#endif
    .tp_name = "pynasm.Register",
    .tp_basicsize = sizeof(RegisterObject),
    .tp_itemsize = 0,
    .tp_as_number = &register_as_number,
    .tp_dealloc = register_dealloc,
    .tp_print = register_print,
    .tp_doc = register_doc,
    .tp_methods = register_methods,
};

static PyNumberMethods register_expression_as_number = {
    .nb_multiply = register_expression_multiply,
    .nb_add = register_expression_add,
};
static PyTypeObject RegisterExpressionClass =
{
    PYTHON23_HEAD_INIT
    .tp_name = "pynasm.RegisterExpression",
    .tp_basicsize = sizeof(RegisterExpressionObject),
    .tp_itemsize = 0,
    .tp_as_number = &register_expression_as_number,
    .tp_dealloc = register_expression_dealloc,
    .tp_print = register_expression_print,
    .tp_doc = register_expression_doc,
    .tp_methods = register_expression_methods,
};

static PyTypeObject LabelClass =
{
    PYTHON23_HEAD_INIT
    .tp_name = "pynasm.Label",
    .tp_basicsize = sizeof(LabelObject),
    .tp_itemsize = 0,
    .tp_dealloc = label_dealloc,
    .tp_print = label_print,
    .tp_doc = label_doc,
    .tp_methods = label_methods,
};

static PyTypeObject InstructionClass =
{
    PYTHON23_HEAD_INIT
    .tp_name = "pynasm.Label",
    .tp_basicsize = sizeof(InstructionObject),
    .tp_itemsize = 0,
    .tp_dealloc = instruction_dealloc,
    .tp_print = instruction_print,
    .tp_doc = instruction_doc,
    .tp_methods = instruction_methods,
};

// -----------------------------------------------------------------------------
//
static void pynasm_free(void*module)
{
    state_t*state = STATE(module);
    memset(state, 0, sizeof(state_t));
}

PyDoc_STRVAR(pynasm_doc,
"The pynasm module is a wrapper for the nasm assembler."
);

static PyMethodDef pynasm_methods[] =
{
    {"function", (PyCFunction)code_new, M_FLAGS, code_new_doc},
    {"assembler", (PyCFunction)code_new, M_FLAGS, code_new_doc},
    {"label", (PyCFunction)label_new, M_FLAGS, label_new_doc},

    /* sentinel */
    {0, 0, 0, 0}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef nasm_moduledef = {
        PyModuleDef_HEAD_INIT,
        "nasm",
        pynasm_doc,
        sizeof(state_t),
        pynasm_methods,
        /*reload*/NULL,
        /*traverse*/NULL,
        /*clear*/NULL,
        pynasm_free,
};
#endif

static inline int register_count()
{
    return REG_ENUM_LIMIT;
}

static void fill_methods(PyTypeObject*cls)
{
    const int count = FIRST_COND_OPCODE;

    PyMethodDef*methods = malloc(sizeof(PyMethodDef)*(count+1));

    int i;
    for(i=0;i<count;i++) {
        const char*name = nasm_insn_names[i];
        /* FIXME: this should really be a descriptor, which means
                  we can't put it into methods */
        methods[i].ml_name = name;
        methods[i].ml_meth = NULL; //FIXME
        methods[i].ml_flags = M_FLAGS;
        methods[i].ml_doc = name;
        //PyDict_SetItemString(dict, "Doc", (PyObject*)&DocClass);
    }

    // sentinel
    methods[i].ml_name = NULL;
    methods[i].ml_meth = NULL;
    methods[i].ml_flags = 0;
    methods[i].ml_doc = NULL;

    cls->tp_methods = methods;
}

static struct {
    char*name;
    enum ccode condition;
} conditions[] = {
#define COND(c) {#c, C_##c}
 COND(A), COND(AE), COND(B), COND(BE), COND(C), COND(E), COND(G), COND(GE),
 COND(L), COND(LE), COND(NA), COND(NAE), COND(NB), COND(NBE), COND(NC), COND(NE),
 COND(NG), COND(NGE), COND(NL), COND(NLE), COND(NO), COND(NP), COND(NS), COND(NZ),
 COND(O), COND(P), COND(PE), COND(PO), COND(S), COND(Z),
};

static void fill_objects(PyObject*dict)
{
    /* create opcode objects */
    const int op_count = FIRST_COND_OPCODE;
    enum opcode o;
    for(o=0;o<op_count;o++) {
        const char*name = nasm_insn_names[o];
        OpcodeObject*op = PyObject_New(OpcodeObject, &OpcodeClass);
        op->name = name;
        op->opcode = o;
        op->condition = -1;
        PyDict_SetItemString(dict, name, (PyObject*)op);
    }

    /* create opcodes with conditionals */
    o = FIRST_COND_OPCODE;
    for(o=FIRST_COND_OPCODE;o<=I_SETcc;o++) {
        const char*base_name = nasm_insn_names[o];
        char name[64];
        int j;
        for(j=0;j<(int)(sizeof(conditions)/sizeof(conditions[0]));j++) {
            sprintf(name, "%s%s", base_name, conditions[j].name);

            /* make lowercase */
            char*c;
            for(c=name;*c;c++) {*c |= 0x60;}

            OpcodeObject*op = PyObject_New(OpcodeObject, &OpcodeClass);
            op->name = name;
            op->opcode = o;
            op->condition = conditions[j].condition;
            PyDict_SetItemString(dict, name, (PyObject*)op);
        }
    }

    /* create register objects */
    const int reg_count = register_count();
    enum reg_enum r;
    for(r=EXPR_REG_START;r<reg_count;r++) {
        const char * name = nasm_reg_names[r - EXPR_REG_START];
        RegisterObject*reg = PyObject_New(RegisterObject, &RegisterClass);
        reg->name = name;
        reg->reg = r;
        reg->reg_flags = nasm_reg_flags[r];
        PyDict_SetItemString(dict, name, (PyObject*)reg);
    }
}

static void init_nasm()
{
    memset(&global_state, 0, sizeof(global_state));
    seg_init(); //nasmlib.c
    init_labels();
    pynasm_ofmt = dummy_ofmt_new();
    pynasm_ofmt->output = pynasm_output;
}

PyObject * PyInit_pynasm(void)
{
#if PY_MAJOR_VERSION >= 3
    PyObject*module = PyModule_Create(&nasm_moduledef);
#else
    PyObject*module = Py_InitModule3("pynasm", pynasm_methods, pynasm_doc);
    CodeClass.ob_type = &PyType_Type;
    RegisterClass.ob_type = &PyType_Type;
    RegisterExpressionClass.ob_type = &PyType_Type;
    OpcodeClass.ob_type = &PyType_Type;
    InstructionClass.ob_type = &PyType_Type;
#endif
    CodeClass.tp_dict = code_tp_dict();
    PyType_Ready(&CodeClass);
    PyType_Ready(&OpcodeClass);
    PyType_Ready(&InstructionClass);
    PyType_Ready(&RegisterClass);
    PyType_Ready(&RegisterExpressionClass);
    
    state_t* state = STATE(module);
    memset(state, 0, sizeof(state_t));

    init_nasm();

    PyObject*module_dict = PyModule_GetDict(module);
    fill_objects(module_dict);
    return module;
}

#if PY_MAJOR_VERSION < 3
void initpynasm(void) {
    PyInit_pynasm();
}
#endif
