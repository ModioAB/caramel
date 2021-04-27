#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import argparse
import unittest

from caramel import config


class TestConfig(unittest.TestCase):
    def test_inifile_argument(self):
        my_ini = "/a/path/to/my_ini_file.ini"

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, {})
        args = parser.parse_args([my_ini])

        self.assertEqual(args.inifile, my_ini)

    def test_inifile_env(self):
        my_ini = "/a/path/to/my_ini_file.ini"
        env = {"CARAMEL_INI": my_ini}

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, env)
        args = parser.parse_args([])

        self.assertEqual(args.inifile, my_ini)

    def test_inifile_argument_env(self):
        my_ini = "/a/path/to/my_ini_file.ini"
        other_ini = "/a/path/to/other_ini_file.ini"
        env = {"CARAMEL_INI": other_ini}

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, env)
        args = parser.parse_args([my_ini])

        self.assertEqual(args.inifile, my_ini)

    def test_no_ini_path(self):
        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, {})

        with self.assertRaises(ValueError):
            parser.parse_args([])
