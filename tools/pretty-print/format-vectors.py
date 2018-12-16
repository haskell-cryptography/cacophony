#!/usr/bin/env python

import jinja2
import json
import os
import sys

def format_input(val):
    if isinstance(val, dict):
        return { k: format_input(v) for k, v in val.items() }
    if isinstance(val, list):
        return map(format_input, val)
    if val is None:
        return "null"
    elif val is False:
        return "false"
    elif val is True:
        return "true"
    else:
        return "\"{0}\"".format(val)

with open(sys.argv[1]) as f:
    vectors = json.loads(f.read())["vectors"]
    vectors = map(format_input, vectors)

    templateLoader = jinja2.FileSystemLoader(searchpath=os.path.dirname(__file__))
    templateEnv = jinja2.Environment(loader=templateLoader)
    template = templateEnv.get_template("vector-template.jinja")
    templateVars = { "vectors": vectors }

with open(sys.argv[1], 'w') as f:
    f.write(template.render(templateVars))
