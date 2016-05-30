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

    ### this does not work ###
    #sym_arg_size = 40  
    # sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
    # argv.append(sym_arg)    #argv[1]

    ### nor this one.. ###

    # Failed to attempt to represent an int number like 200
    sym_arg = claripy.BVS(0x41414141, 32)
    argv.append(sym_arg)    #argv[1]
    argv.append("hello") # argv[2]

    state = project.factory.entry_state(args=argv)
    
    path_group = project.factory.path_group(state)

    path_group = path_group.explore(find=0x080485b1, avoid=(0x0804854f,0x0804851f))

    # cry
    # In [1]: print path_group
    # <PathGroup with 2 deadended>

    print path_group.deadended
	#[<Path with 30 runs (at 0x9000060)>, <Path with 36 runs (at 0x9000060)>]

	import IPython; IPython.embed()


if __name__ == '__main__':
    print main()
