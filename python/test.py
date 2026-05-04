from util import spec_parser

endpoints = spec_parser.parse_spec('petstore.yaml')
print(endpoints[0].path)