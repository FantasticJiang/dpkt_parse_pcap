def add_dict_kv(d: dict, key: str):
    try:
        d[key] += 1
    except KeyError:
        d[key] = 1


def write_dict_to_file(target_dict, filepath: str, file_suffix: str = '', ):
    """
    用于将字典或字典列表写入文件
    target_dict: 待写入文件的字典
    filepath: 文件路径
    file_suffix: 文件名后缀（可选）
    一般写入字典，传filepath即可，若是报文字段解析结果，可传入file_suffix表示字段。
    示例：filepath='./test', file_suffix='_host.log'，表示将test报文的host解析结果写入'test_host.log'文件。
    """
    import json
    filename = filepath + file_suffix
    if isinstance(target_dict, dict) and target_dict:
        f = open(filename, 'w')
        try:
            for key, value in target_dict.items():
                f.write(f"{key}: {str(value)}\n")
        finally:
            f.close()
            target_dict.clear()
    elif isinstance(target_dict, list):
        field_list = ['Referer', 'X-Requested-With', 'bundleId', 'User-Identity', 'Q-UA2', 'X-Umeng-Sdk']
        f = open(filename, 'w')
        count = 0
        for dict_num in range(len(target_dict)):
            sub_dict = target_dict[dict_num]
            if sub_dict:
                if count > 0:
                    f.write('\n')
                f.write(f'[{field_list[dict_num]}]\n')
                for key, value in sub_dict.items():
                    f.write(f"{key}: {value}\n")
                f.write('\n')
                sub_dict.clear()
                count += 1
        f.close()


def write_dict_bysort(target_dict, filepath: str, file_suffix: str = '', ):
    if target_dict:
        filename = filepath + file_suffix
        f = open(filename, 'w')
        for k in sorted(target_dict):
            f.write(k + ':' + str(target_dict[k]) + '\n')
        f.close()
        target_dict.clear()


