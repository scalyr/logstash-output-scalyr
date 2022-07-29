#
# Copyright 2014 Scalyr Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
# Utility scripts which concatenates multiple root CA certs into a single pem formatted file with
# multiple CA certs. Taken from https://github.com/scalyr/scalyr-agent-2/blob/master/build_package.py
"""

import os
import glob


def glob_files(path):
    """Returns the paths that match the specified path glob (based on current working directory).
    @param path: The path with glob wildcard characters to match. This should use a forward slash as the separator,
        regardless of the platform's separator.
    @return: The list of matched paths.
    """
    return glob.glob(convert_path(path))


def make_path(parent_directory, path):
    """Returns the full path created by joining path to parent_directory.
    This method is a convenience function because it allows path to use forward slashes
    to separate path components rather than the platform's separator character.
    @param parent_directory: The parent directory. This argument must use the system's separator character. This may be
        None if path is relative to the current working directory.
    @param path: The path to add to parent_directory. This should use forward slashes as the separator character,
        regardless of the platform's character.
    @return:  The path created by joining the two with using the system's separator character.
    """
    if parent_directory is None and os.path.sep == "/":
        return path

    if parent_directory is None:
        result = ""
    elif path.startswith("/"):
        result = ""
    else:
        result = parent_directory

    for path_part in path.split("/"):
        if len(path_part) > 0:
            result = os.path.join(result, path_part)

    return result


def convert_path(path):
    """Converts the forward slashes in path to the platform's separator and returns the value.
    @param path: The path to convert. This should use forward slashes as the separator character, regardless of the
        platform's character.
    @return: The path created by converting the forward slashes to the platform's separator.
    """
    return make_path(None, path)


def cat_files(file_paths, destination, convert_newlines=False):
    """Concatenates the contents of the specified files and writes it to a new file at destination.
    @param file_paths: A list of paths for the files that should be read. The concatenating will be done in the same
        order as the list.
    @param destination: The path of the file to write the contents to.
    @param convert_newlines: If True, the final file will use Windows newlines (i.e., CR LF).
    """
    dest_fp = open(destination, "w")
    for file_path in file_paths:
        in_fp = open(file_path, "r")
        for line in in_fp:
            if convert_newlines:
                line.replace("\n", "\r\n")
            dest_fp.write(line)
        in_fp.close()
    dest_fp.close()


if __name__ == "__main__":
    cat_files(
            glob_files("lib/scalyr/certs/*_root.pem"),
            "lib/scalyr/certs/ca_certs.crt",
            convert_newlines=True,
    )
