import angr
import claripy
import logging

# Based on article from Phrack: http://phrack.org/issues/60/10.html

# The aim of this example is to find the integer overflow symbolically.

# Sample Execution:
# $ ./width1 65535 hello
# Oh no you don't!

# comparing when the int overflow occurs:
# $ ./width1 65536 hello
# s = 0
# *** buffer overflow detected ***: ./width1 terminated
# ======= Backtrace: =========
# /lib/i386-linux-gnu/libc.so.6(+0x68e4e)[0xf7596e4e]


def main():

    logging.getLogger('angr.path_group').setLevel(logging.DEBUG)

    # Load project
    project = angr.Project("./width1", load_options={'auto_load_libs': False})

    argv = [project.filename]   #argv[0]

    # Set up symbolic values
    input_size = 10; 
    sym_arg = claripy.BVS("the_integer", input_size * 8)

    argv.append(sym_arg)    #argv[1]
    argv.append("hello") # argv[2]

    state = project.factory.entry_state(args=argv)
    # state.libc.buf_symbolic_bytes=input_size + 20     <=== useless at this phase.


    # If we try to add contstaints (numbers specifically) since we do know
    # that the first argument should be numbers only, it does find some paths
    # but throws unsat errors.

    # for byte in sym_arg.chop(8):
    #     state.add_constraints(byte >= 48) # Chars 0-9
    #     state.add_constraints(byte <= 57)
    #     state.add_constraints(byte != '\x00') # null

    path_group = project.factory.path_group(state)
    # path_group = project.factory.path_group(save_unconstrained=True)

    path_group = path_group.explore(find=0x084854f, avoid=(0x0804854f,0x0804851f))

    # In [1]: print path_group.deadended
    # [<Path with 30 runs (at 0x9000060)>, <Path with 36 runs (at 0x9000060)>]

    # In [2]: print path_group.deadended[0].state.se.any_str(sym_arg)
    # here prints weird chars that break python

    # In [3]: print path_group.deadended[1].state.se.any_str(sym_arg)
    # +999948367

if __name__ == '__main__':
    print main()