import os
import subprocess
import unittest

DEBUG=False


def eval_command(*commands, return_binary=False):
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
        "function get_creds() { echo 'some_strong_password' 'ca475acf0f1ca4b0'; }"
        # "set -evxo pipefail -B"
    ] + list(commands)
    commands = " && ".join(command_list)
    if DEBUG:
        print(f"{commands!r}")

    output, exit_code = process.communicate(input=commands.encode())
    assert exit_code == None
    result = output if return_binary else output.decode(errors='ignore')
    if DEBUG:
        print(f"{result!r}")
    return result

def pipeline(*commands):
    return " | ".join(commands)


class TestStringMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # base64_encode = "base64"
        # base64_decode = f"{base64_encode} -d"
        # binary_to_hex = "binary_to_hex"
        # hex_to_binary = "hex_to_binary"
        # remove_null_byte = "tr -d \"\\r\\n\\0\""
        cls.encoded_value = "secrets"
        cls.encoded_value_with_openssl_version_1_1_1 = "U2FsdGVkX1/KR1rPDxyksAB2r3M/7XTT8xt3bJLksH4=\n"
        cls.encoded_value_with_openssl_version_3_0_13 = "AHavcz/tdNPzG3dskuSwfg==\n"
        
    def test_encode(self):
        encoded_value = eval_command(
            pipeline(
                "echo -n 'secrets'",
                "gitencrypt_crypt",
            ),
        )
        self.assertEqual(encoded_value, "U2FsdGVkX1/KR1rPDxyksAB2r3M/7XTT8xt3bJLksH4=\n")

        decoded_value = eval_command(
            pipeline(
                f"echo -en '{self.encoded_value_with_openssl_version_1_1_1}'",
                "gitencrypt_decrypt",
            ),
        )
        self.assertEqual(decoded_value, "secrets")

        decoded_value = eval_command(
            pipeline(
                f"echo -en '{self.encoded_value_with_openssl_version_3_0_13}'",
                "gitencrypt_decrypt",
            ),
        )
        self.assertEqual(decoded_value, "secrets")

        decoded_value = eval_command(
            pipeline(
                """
                a="SGVsbG8K"
                is_text_base64 $a
                echo "$?"
                """
            ),
        )

        self.assertEqual(decoded_value, "0\n")

        decoded_value = eval_command(
            pipeline(
                """
                a="Hello"
                is_text_base64 $a
                echo "$?"
                """
            ),
        )

        self.assertEqual(decoded_value, "1\n")

        # ---

if __name__ == "__main__":
    unittest.main()
