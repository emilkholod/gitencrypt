import os
import subprocess

def eval_command(*commands, return_binary=False, print_command=False):
    process = subprocess.Popen(
        # For UNIX
        # ['/bin/bash'], 
        # For Windows and UNIX
        ["bash"],
        shell=True, 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE,
        env=dict(
            os.environ,
            GITENCRYPT_SALT_FIXED='ca475acf0f1ca4b0',
            GITENCRYPT_PASS_FIXED='some_strong_password',
            GITENCRYPT_LOG_PATH='./log.txt',
        ),
    )
    command_list = [
        ". ./base_script", 
        # "set -evxo pipefail -B"
    ] + list(commands)
    commands = " && ".join(command_list)
    if print_command:
        print(f"{commands!r}")

    output, exit_code = process.communicate(input=commands.encode())
    assert exit_code == None
    result = output if return_binary else output.decode(errors='ignore') 
    print(f"{result!r}")
    return result

def pipeline(*commands):
    return " | ".join(commands)

def run_tests():
    base64_encode = "base64"
    base64_decode = f"{base64_encode} -d"
    binary_to_hex = "binary_to_hex"
    hex_to_binary = "hex_to_binary"
    remove_null_byte = "tr -d \"\\r\\n\\0\""
    add_hex_prefix = "sed \"s/^/{53616c7465645f5f${GITENCRYPT_SALT_FIXED}}/\""


    # TODO: Нужно в binary записать соль, а потом уже конвертить в base64
    encoded_value = "secrets"
    encoded_value_with_openssl_version_1_1_1 = "U2FsdGVkX1/KR1rPDxyksAB2r3M/7XTT8xt3bJLksH4=\n"
    encoded_value_with_openssl_version_3_0_13 = "AHavcz/tdNPzG3dskuSwfg==\n"

    # ---
    # TODO: Check this for both versions
    encoded_value = eval_command(
        pipeline(
            "echo -n 'secrets'",
            "gitencrypt_crypt",
        ),
    )
    assert encoded_value == "U2FsdGVkX1/KR1rPDxyksAB2r3M/7XTT8xt3bJLksH4=\n"

    decoded_value = eval_command(
        pipeline(
            f"echo -en '{encoded_value_with_openssl_version_1_1_1}'",
            "gitencrypt_decrypt",
        ),
    )
    assert decoded_value == "secrets"

    decoded_value = eval_command(
        pipeline(
            f"echo -en '{encoded_value_with_openssl_version_3_0_13}'",
            "gitencrypt_decrypt",
        ),
    )
    assert decoded_value == "secrets"

    decoded_value = eval_command(
        pipeline(
            """
            a="SGVsbG8K"
            if is_text_base64 $a; then
                echo -en "base64"
            else
                echo -en "NOT base64"
            fi
            """
        ),
    )

    assert decoded_value == "base64"

    decoded_value = eval_command(
        pipeline(
            """
            a="Hello"
            if is_text_base64 $a; then
                echo -en "base64"
            else
                echo -en "NOT base64"
            fi
            """
        ),
    )

    assert decoded_value == "NOT base64"

    # ---

if __name__ == "__main__":
    run_tests()
