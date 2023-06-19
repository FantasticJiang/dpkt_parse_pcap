def add_dict_kv(d: dict, key: str):
    try:
        d[key] += 1
    except KeyError:
        d[key] = 1