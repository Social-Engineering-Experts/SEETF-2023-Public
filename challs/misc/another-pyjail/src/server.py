from types import CodeType

def clear(code):
    return CodeType(
        code.co_argcount, code.co_kwonlyargcount, code.co_nlocals, 
        code.co_stacksize, code.co_flags, code.co_code, 
        # No consts for youuu
        tuple(clear(c) if isinstance(c, CodeType) else None for c in code.co_consts),
        # No names for youuuu
        (), 
        code.co_varnames, code.co_filename, code.co_name,
        code.co_firstlineno, code.co_lnotab, code.co_freevars, 
        code.co_cellvars
    )

print(eval(clear(compile(input("> "), __name__, "eval")), {'__builtins__': {}}, {})(getattr))