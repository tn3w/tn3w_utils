# TN3W_Utils
A consolidation of all tools created so far as a Python package


All functions in this package:
```python
# Basic Tools
random_string(length, with_numbers, with_letters, with_punctuation)
random_font()
shorten_text(text, length)
list_remove_duplicates(origin_list)
reverse_list(origin_list)
get_system_architecture()
get_console_columns()
find_missing_numbers_in_range(range_start, range_end, data)
get_password_strength(password)
is_password_pwned(password, session)
EmptyWith().
    __enter__()
    __exit__(exc_type, exc_value, traceback)
download_file(url, dict_path, operation_name, file_name, session, return_as_bytes, quite)
AtExit().
    register(func, *args, **kwargs)
    remove_atexit(atexit_id)

# File Tools
JSON.
    load(file_name, default)
    dump(data, file_name)
Block(block_size, file_name).
    _get_id(index)
    _write_data(block_data)
    add_data(index, new_data)
read(file_name, is_bytes, default)
write(data, file_name, is_bytes)
SecureDelete.
    list_files_and_directories(directory_path)
    file(file_path, quite)
    directory(directory_path, quite)

# Cryptographic Tools
FastHashing(salt, without_salt).
    hash(plain_text, salt_length)
    compare(plain_text, hashed_value)
Hashing(salt, without_salt).
    hash(plain_text, hash_length)
    compare(plain_text, hashed_value)
SymmetricEncryption(password, salt_length).
    encrypt(plain_text)
    decrypt(cipher_text)
AsymmetricEncryption(public_key, private_key).
    generate_keys(key_size)
    encrypt(plain_text)
    decrypt(cipher_text)
    sign(plain_text)
    verify_sign(signature, plain_text)
NoEncryption().
    encrypt(plain_text)
    decrypt(cipher_text)
derive_password(password, salt)

# User-Agent Tools
random_ua()

# IP-Address Tools
shorten_ipv6(ip_address)
ipv4_to_ipv6(ipv4_address)
is_valid_ip(ip_address)
get_client_ip(request)
get_ip_info(ip_address, cache_path, save_securely)

# Web Tools
remove_args_from_url(url)
WebPage.
    client_language(request, default)
    _minimize_tag_content(html, tag)
    minimize(html)
    _translate_text(text_to_translate, from_lang, to_lang)
    translate(html, from_lang, to_lang)
    render_template(file_path, html, **args)
render_template(file_name, request, template_dir, template_language, **args)

# Image Tools
show_image_in_console(image_bytes)
random_website_logo(name)
convert_image_to_base64(file_path)
is_valid_image(image_data)
resize_image(image_data, target_size)

# Software Tools
macos_get_installer_and_volume_path()
Linux.
    get_package_manager()
    install_package(package_name, quite)
GnuPG.
    path
    get_download_link(session)
Captcha(captcha_secret, data).
    generate()
    verify(client_input, crypted_captcha_prove)
```