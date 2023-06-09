def trim_end(s, needle):
    if not s.endswith(needle):
        return None

    return s[: -len(needle)]


def trim_start(s, needle):
    if not s.startswith(needle):
        return None

    return s[len(needle) :]
