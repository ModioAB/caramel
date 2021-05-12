#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""tests.test_config contains the unittests for caramel.config"""
import argparse
import unittest

from caramel import config


class TestConfig(unittest.TestCase):
    """Tests for the caramel.config library"""

    def test_inifile_argument(self):
        """path as argument, no path in the environment"""
        my_ini = "/a/path/to/my_ini_file.ini"

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, {})
        args = parser.parse_args([my_ini])

        self.assertEqual(args.inifile, my_ini)

    def test_inifile_env(self):
        """path in the environment, no path argument"""
        my_ini = "/a/path/to/my_ini_file.ini"
        env = {"CARAMEL_INI": my_ini}

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, env)
        args = parser.parse_args([])

        self.assertEqual(args.inifile, my_ini)

    def test_inifile_argument_env(self):
        """different paths as argument and in environment,
        argument takes priority"""
        my_ini = "/a/path/to/my_ini_file.ini"
        other_ini = "/a/path/to/other_ini_file.ini"
        env = {"CARAMEL_INI": other_ini}

        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, env)
        args = parser.parse_args([my_ini])

        self.assertEqual(args.inifile, my_ini)

    def test_no_ini_path(self):
        """no path in either argument or evironment, should raise ValueError"""
        parser = argparse.ArgumentParser()
        config.add_inifile_argument(parser, {})

        with self.assertRaises(ValueError):
            parser.parse_args([])
