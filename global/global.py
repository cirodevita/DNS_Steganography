def countConsonantsandVolwes(string):
    vowel = set("aeiouAEIOU")
    v_count = 0
    c_count = 0
    for i in string:
        if i in vowel:
            v_count = v_count + 1
        elif ('a' <= i <= 'z') or ('A' <= i <= 'Z'):
            c_count += 1

    return c_count, v_count
