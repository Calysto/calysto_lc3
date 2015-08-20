import json
import os
import sys

from IPython.kernel.kernelspec import install_kernel_spec
from IPython.utils.tempdir import TemporaryDirectory

kernel_json = {
    "argv": [
        sys.executable, 
        "-m", "calysto_lc3", 
        "-f", "{connection_file}"
    ],
    "display_name": "Calysto LC3",
    "language": "asm",
    "codemirror_mode": "nasm",
}

def install_my_kernel_spec(user=True):
    with TemporaryDirectory() as td:
        os.chmod(td, 0o755) # Starts off as 700, not user readable
        with open(os.path.join(td, 'kernel.json'), 'w') as f:
            json.dump(kernel_json, f, sort_keys=True)
        # TODO: Copy resources once they're specified

        print('Installing IPython kernel spec')
        install_kernel_spec(td, 'calysto_lc3', user=user, replace=True)

def main(argv=None):
    install_my_kernel_spec()

if __name__ == '__main__':
    main()
