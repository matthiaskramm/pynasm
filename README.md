About:
------

pynasm is a python wrapper around nasm. It's still in very early stages,
but if you're feeling adventurous, you can try the following snippet:

```python
from pynasm import *

with assembler() as get_max_cores:
    push(ebx)
    push(ecx)
    push(edx)
    mov(eax,4) 
    xor(ecx,ecx)
    cpuid()
    shr(eax,26)
    inc(eax)
    pop(edx)
    pop(ecx)
    pop(ebx)
    ret()

print("maximum number of cores:", get_max_cores())
```

