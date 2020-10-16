from flask import redirect
import html


def pop_null(params_dict):
    new_params = {}
    for key in list(params_dict.keys()):
        if params_dict[key] != '':
            new_params[key] = params_dict[key]
    return new_params


def dict_to_get_params(params):
    return "&".join(["{}={}".format(key, params[key]) for key in list(params.keys())])


def redirect_post_to_get(req):
    params = req.form.to_dict()
    params = pop_null(params)
    return redirect("{}?{}".format(req.path, dict_to_get_params(params)))
