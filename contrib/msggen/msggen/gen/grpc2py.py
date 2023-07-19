"""Converts the GRPC messages back to parsed JSON dicts in python.

This can be used to expose a local JSON-RPC socket but then talk to
the node over the GRPC interface.

"""
from msggen.model import ArrayField, CompositeField, EnumField, PrimitiveField, Service
from msggen.gen import IGenerator
import logging
from textwrap import dedent
from typing import TextIO
import re


def decamelcase(c):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', c).lower()


override = {
    'ListPeers.peers[].channels[].state_changes[]': None,
}


class Grpc2PyGenerator(IGenerator):
    def __init__(self, dest: TextIO):
        self.dest = dest
        self.logger = logging.getLogger(__name__)

        # Expressions used to convert the right-hand side into the
        # format we expect in the dict.
        self.converters = {
            'hex': "hexlify(m.{name})",
            'pubkey': "hexlify(m.{name})",
            'secret': "hexlify(m.{name})",
            'signature': "hexlify(m.{name})",
            'txid': "hexlify(m.{name})",
            'hash': "hexlify(m.{name})",
            'string': "m.{name}",
            'u8': "m.{name}",
            'u16': "m.{name}",
            'u32': "m.{name}",
            'u64': "m.{name}",
            's8': "m.{name}",
            's16': "m.{name}",
            's32': "m.{name}",
            's64': "m.{name}",
            'integer': "m.{name}",
            'boolean': "m.{name}",
            'short_channel_id': "m.{name}",
            'msat': "amount2msat(m.{name})",
            'number': "m.{name}",
        }

    def generate_responses(self, service):
        for meth in service.methods:
            res = meth.response
            self.generate_composite(None, res)

    def write(self, text: str, cleanup: bool = True) -> None:
        if cleanup:
            self.dest.write(dedent(text))
        else:
            self.dest.write(text)

    def generate(self, service: Service) -> None:
        self.write("""\
        # This file was automatically derived from the JSON-RPC schemas in
        # `doc/schemas`. Do not edit this file manually as it would get
        # overwritten.

        import json


        def hexlify(b):
            return b if b is None else b.hex()


        def amount2msat(a):
            return a.msat


        def remove_default(d):
            # grpc is really not good at empty values, they get replaced with the type's default value...
            return {k: v for k, v in d.items() if v is not None and v != ""}
        """)

        self.generate_responses(service)

    def generate_enum(self, prefix, field: EnumField):
        name = field.name.normalized()
        prefix = f"{prefix}_{str(name).lower()}"
        if field.path.endswith("[]"):
            self.converters[field.path] = "str(i)"
        else:
            self.converters[field.path] = "str(m.{{name}})"

    def generate_composite(self, prefix, field: CompositeField):
        if override.get(field.path, "") is None:
            return
        name = field.name.normalized()
        if prefix:
            prefix = f"{prefix}_{str(name).lower()}"
        else:
            prefix = f"{str(name).lower()}"

        for f in field.fields:
            if isinstance(f, CompositeField):
                self.generate_composite(prefix, f)

            elif isinstance(f, ArrayField) and isinstance(f.itemtype, CompositeField):
                self.generate_composite(prefix, f.itemtype)

            elif isinstance(f, ArrayField) and isinstance(f.itemtype, EnumField):
                self.generate_enum(prefix, f.itemtype)

        converter_name = f"{prefix}2py"
        self.write(f"""

        def {converter_name}(m):
            return remove_default({{
        """)

        for f in field.fields:
            name = f.normalized()
            if isinstance(f, PrimitiveField):
                typ = f.typename

                rhs = self.converters[typ].format(name=f.name)

                self.write(f'        "{name}": {rhs},  # PrimitiveField in generate_composite\n', cleanup=False)

            elif isinstance(f, ArrayField) and isinstance(f.itemtype, PrimitiveField):
                rhs = self.converters[f.itemtype.typename].format(name=name)
                self.write(f'        "{name}": [{rhs} for i in {rhs}], # ArrayField[primitive] in generate_composite\n', cleanup=False)

            elif isinstance(f, ArrayField):
                if override.get(f.path, "") is None:
                    continue
                rhs = self.converters[f.path]

                self.write(f'        "{name}": [{rhs} for i in m.{name}],  # ArrayField[composite] in generate_composite\n', cleanup=False)

            elif isinstance(f, CompositeField):
                rhs = self.converters[f.path].format(name=f.name)
                # self.write(f'        "{name}": {rhs}, # CompositeField in generate_composite\n', cleanup=False)

            elif isinstance(f, EnumField):
                name = f.name
                self.write(f'        "{name}": str(m.{f.name.normalized()}),  # EnumField in generate_composite\n', cleanup=False)

        self.write(f"    }})\n", cleanup=False)

        # Add ourselves to the converters so if we were generated as a
        # dependency for a composite they can find us again. We have
        # two variants: an array one where the items are going to be
        # called "i" so we don't clobber and one-of where the field is
        # "m.{name}" which will be filled by the caller.
        if field.path.endswith("[]"):
            self.converters[field.path] = f"{converter_name}(i)"
        else:
            self.converters[field.path] = f"{converter_name}(m.{{name}})"
