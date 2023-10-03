from esm.esm import EncryptedStringMatcher

if __name__ == "__main__":
    matcher = EncryptedStringMatcher()

    s1 = matcher.encrypt_string("hello world")
    s2 = matcher.encrypt_string("hello world")
    assert matcher.are_strings_equal(s1, s2) == True

    s1 = matcher.encrypt_string("hello world")
    s2 = matcher.encrypt_string("bye world")
    assert matcher.are_strings_equal(s1, s2) == False
