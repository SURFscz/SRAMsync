def render_templated_string(template_string, **kw):
    """
    Contrain the possible keywords for substutution in a templated string.
    """
    return template_string.format(**kw)