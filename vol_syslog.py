#!/usr/bin/env python3

# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import volatility.cli
import renderersyslog
import configparser

from urllib import parse, request
from volatility.cli import text_renderer
from volatility import framework
from volatility.framework.automagic import stacker
from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration


config = configparser.ConfigParser()
config.read('config_syslog.ini')
pluginname = str(config["plugin"]["value"])
filename = str(config["location"]["file"])

framework.import_files(volatility.plugins, True)
renderers = dict([(x.name.lower(), x) for x in framework.class_subclasses(text_renderer.CLIRenderer)])
ctx = contexts.Context()

single_location = "file:" + request.pathname2url(filename)

ctx.config['automagic.LayerStacker.single_location'] = single_location
automagics = automagic.available(ctx)
plugin_list = framework.list_plugins()

plugin = plugin_list[pluginname]
automagics = automagic.choose_automagic(automagics, plugin)
if ctx.config.get('automagic.LayerStacker.stackers', None) is None:
     ctx.config['automagic.LayerStacker.stackers'] = stacker.choose_os_stackers(plugin)
base_config_path = "plugins"
plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
progress_callback = volatility.cli.MuteProgress()



constructed = plugins.construct_plugin(ctx, automagics, plugin, base_config_path, progress_callback, volatility.cli)
renderers["syslog"]().render(constructed.run())


