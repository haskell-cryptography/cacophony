#!/usr/bin/env python

import jinja2
import json
import sys

def format_input(val):
    if isinstance(val, dict):
        return { k: format_input(v) for k, v in val.iteritems() }
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

vectors = json.load(sys.stdin)["vectors"]
vectors = map(format_input, vectors)

templateLoader = jinja2.FileSystemLoader(searchpath=".")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "vector_template.jinja"
template = templateEnv.get_template(TEMPLATE_FILE)
templateVars = { "vectors": vectors }
print(template.render(templateVars))
