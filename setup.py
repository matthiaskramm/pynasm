from distutils.core import setup, Extension

version = "0.0.1"

nasm_sources = """
nasm nasmlib ver raa saa rbtree float insnsa insnsb directiv assemble
labels hashtbl crc64 parser output/outform output/outlib output/nulldbg
output/nullout output/outbin output/outaout output/outcoff output/outelf
output/outelf32 output/outelf64 output/outelfx32 output/outobj
output/outas86 output/outrdf2 output/outdbg output/outieee
output/outmac32 output/outmac64 preproc quote pptok macros listing eval
exprlib stdscan strfunc tokhash regvals regflags ilog2 lib/strlcpy
preproc-nop disasm sync insnsd insnsn regs regdis
"""

sources = ["pynasm.c", "ofmt.c"]
sources += ["nasm/%s.c" % src for src in (s.strip() for s in nasm_sources.split()) if src]
compiler_options=["-Dmain=nasm_main", "-Wno-unused", "-Wno-unused-parameter"]

pynasm_module = Extension(
    name = "pynasm", 
    sources = sources,
    include_dirs = ["nasm", "."],
    extra_compile_args = compiler_options,
)

setup(name = "pynasm",
      version = version,
      description = "A python wrapper for nasm",
      author = "Matthias Kramm",
      author_email = "matthias@quiss.org",
      url = "http://github.com/matthiaskramm/pynasm/",
      license = "GPL",
      ext_modules = [pynasm_module]
     )
