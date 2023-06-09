from dataclasses import dataclass

from .strings import trim_start


@dataclass(frozen=True)
class Substitutions:
    caller: str
    bucket: str


def _visit_name(params, elem):
    elem.text = params.bucket


def _visit_key(params, elem):
    elem.text = trim_start(elem.text, params.caller + "/")


def _visit_contents(params, elem):
    visit(params, elem, visitors=_CONTENTS_VISITORS)


def _visit_common_prefixes(params, elem):
    visit(params, elem, visitors=_COMMON_PREFIXES_VISITORS)


def _make_visitors(**kwargs):
    ret = dict()
    for k, v in kwargs.items():
        k = "{http://s3.amazonaws.com/doc/2006-03-01/}" + k
        ret[k] = v

    return ret


_COMMON_PREFIXES_VISITORS = _make_visitors(Prefix=_visit_key)

_CONTENTS_VISITORS = _make_visitors(Key=_visit_key)

VISITORS = _make_visitors(
    Prefix=_visit_key,
    Contents=_visit_contents,
    Name=_visit_name,
    CommonPrefixes=_visit_common_prefixes,
)


def visit(params, element, visitors=VISITORS):
    for child in element:
        visitor = visitors.get(child.tag)
        if not visitor:
            continue

        visitor(params, child)
