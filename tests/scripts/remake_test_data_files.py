#!/usr/bin/env python3

"""Rebuild the files in tests/data_files and check the result.
"""

import argparse
import difflib
import glob
import os
import shutil
import subprocess
import sys
from typing import Iterator, List


class Comparator:
    def __init__(self, old_dir: str) -> None:
        self.errors = 0
        self.old_dir = old_dir
        self.new_dir = old_dir + '.new'
        os.makedirs(self.new_dir, exist_ok=True)

    def error(self, msg: str) -> None:
        self.errors += 1
        sys.stderr.write(msg + '\n')

    @staticmethod
    def subprocess_output_lines(*args, **kwargs) -> List[str]:
        kwargs['universal_newlines'] = True
        output = subprocess.check_output(*args, **kwargs)
        return output.split('\n')

    def files_to_keep(self) -> Iterator[str]:
        yield from glob.glob('*conf', root_dir=self.old_dir)

    def prepare_remake(self) -> None:
        for filename in self.files_to_keep():
            shutil.copy(os.path.join(self.old_dir, filename),
                        os.path.join(self.new_dir, filename))

    def do_remake(self) -> None:
        subprocess.check_call(['make', 'programs'])
        makefile = os.path.join(os.path.abspath(self.old_dir), 'Makefile')
        try:
            subprocess.check_call(['make', '-f', makefile, '-k'],
                                  cwd=self.new_dir)
        except subprocess.CalledProcessError as exn:
            self.error('Failed to make all files!')

    @staticmethod
    def file_is_der(filename: str) -> bool:
        with open(filename, 'rb') as inp:
            b = inp.read(1)
            return b == '\x30'

    def dump_file(self, filename: str) -> str:
        if filename.endswith('.crl'):
            cmd = ['crl']
        elif 'prv' in filename:
            cmd = ['pkey']
        elif 'pub' in filename:
            cmd = ['pkey', '-pubin']
        else:
            cmd = ['x509']
        if self.file_is_der(filename):
            cmd += ['-inform', 'DER']
        cmd_text = '# {}\n'.format(' '.join(cmd[-1:]))
        output = subprocess.check_output(['openssl'] + cmd +
                                         ['-text', '-in', filename])
        # TODO: strip variable parts
        # TODO: detect invalid signatures etc.
        return cmd_text + output.decode('utf-8')

    def compare_dumps(self, filename: str,
                      old_dump: str, new_dump: str) -> None:
        differ = difflib.Differ()
        diff = list(differ.compare(old_dump, new_dump))
        if diff:
            self.error('The new version of {} is different!'.format(filename))

    def compare_one_file(self, filename: str) -> None:
        if not os.path.exists(os.path.join(self.new_dir, filename)):
            self.error('Missing file: ' + filename)
            return
        old_dump = self.dump_file(os.path.join(self.old_dir, filename))
        new_dump = self.dump_file(os.path.join(self.new_dir, filename))
        self.compare_dumps(filename, old_dump, new_dump)

    def compare_files(self) -> None:
        final_files = self.subprocess_output_lines(['make', 'list_final'],
                                                   cwd=self.old_dir)
        for filename in final_files:
            self.compare_one_file(filename)
        # TODO: check that new_dir has no unexpected file


def main() -> bool:
    comparator = Comparator('tests/data_files')
    comparator.prepare_remake()
    comparator.do_remake()
    comparator.compare_files()
    return comparator.errors == 0

if __name__ == '__main__':
    if not main():
        exit(1)
