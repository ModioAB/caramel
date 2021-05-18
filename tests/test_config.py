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


class TestGetConfigValue(unittest.TestCase):
    """Tests for caramel.config._get_config_value"""

    def test_argument_only(self):
        """Test that a value will be returned even without settings or an
        env-variable"""
        variable_value = "very important configuration detail"
        variable_name = "my-var"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, variable_value)
        value = config._get_config_value(arguments, variable_name, env={})
        self.assertEqual(variable_value, value)

    def test_argument_preferred(self):
        """Test to see that argument value is preferred when the variable exists in
        settings and environment as well"""
        variable_name = "my-var"
        arg_value = "The best stuff around"
        env_name = "CARAMEL_MY_VAR"

        arguments = argparse.Namespace()
        setattr(arguments, variable_name, arg_value)
        value = config._get_config_value(
            arguments,
            variable_name,
            settings={variable_name: "The worstest"},
            env={env_name: "The worst stuff"},
        )
        self.assertEqual(arg_value, value)

    def test_env_preferred(self):
        """Test to see that env value is preferred when the variable exists in
        settings as well"""
        variable_name = "my-var"
        env_value = "The best stuff around"
        env_name = "CARAMEL_MY_VAR"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, None)
        value = config._get_config_value(
            arguments,
            variable_name,
            settings={variable_name: "The worstest"},
            env={env_name: env_value},
        )
        self.assertEqual(env_value, value)

    def test_settings_only(self):
        """Test to see that the value from settings is returned when no argument or
        env-variable"""
        variable_name = "my-var"
        settings_value = "Come on Toshi, you're sooo good"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, None)
        value = config._get_config_value(
            arguments,
            variable_name,
            settings={variable_name: settings_value},
            env={},
        )
        self.assertEqual(settings_value, value)

    def test_settings_only_no_argument(self):
        """Test to see that the value from settings is returned when variable is not
        settable from the commandline and no env-variable"""
        variable_name = "my-var"
        settings_value = "Come on Toshi, you're sooo good"
        arguments = argparse.Namespace()
        value = config._get_config_value(
            arguments,
            variable_name,
            settings={variable_name: settings_value},
            env={},
        )
        self.assertEqual(settings_value, value)

    def test_different_setting_name_only(self):
        """Test to see that the value from settings is returned when the name of the
        settings differs from the varaible name"""
        variable_name = "my-var"
        setting_name = "something.very.different"
        settings_value = "Come on Toshi, you're sooo good"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, None)
        value = config._get_config_value(
            arguments,
            variable_name,
            setting_name=setting_name,
            settings={setting_name: settings_value},
            env={},
        )
        self.assertEqual(settings_value, value)

    def test_nothing(self):
        """Test to see that if no value has been supplied as either an argument,
        environment-variable or setting it returns None"""
        variable_name = "my-var"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, None)
        value = config._get_config_value(
            arguments,
            variable_name,
            settings={},
            env={},
        )
        self.assertEqual(None, value)

    def test_requierd_nothing(self):
        """Test to see that if no value has been supplied as either an argument,
        environment-variable or setting and the variable is required a ValueError
         will be raised"""
        variable_name = "my-var"
        arguments = argparse.Namespace()
        setattr(arguments, variable_name, None)
        with self.assertRaises(ValueError):
            config._get_config_value(
                arguments,
                variable_name,
                required=True,
                settings={},
                env={},
            )
