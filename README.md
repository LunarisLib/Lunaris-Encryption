# Lunaris Encryption Library

Some algorithms available from these files are not very secure, but the RSA 32 bit is good enough. Yes, hackers may break your stuff, but hopefully they are at least qualified, I mean, it's not someone random listening to your connection.

This is my first project related to security/encryption. Hopefully it is good enough for my projects, performance and security wise.


## How to add the project to your project

### Using FetchContent

You can create a file like `cmake/installLibrary.cmake` and put in there:

```cmake
include(FetchContent)

FetchContent_Declare(
    lunaris-encryption
    GIT_REPOSITORY https://github.com/LunarisLib/Lunaris-Encryption.git
    GIT_TAG        (put version here)
)
FetchContent_MakeAvailable(lunaris-encryption)
```

This will allow you to download and link the library like:

```cmake
# ...

include(cmake/installLibrary.cmake) # does the FetchContent

target_link_libraries(YourProjectName PRIVATE
    lunaris::lunaris-encryption
)
```

### Using find_package()

If you get the install version with the lib and headers and want to avoid recompiling the library yourself, you can do

```cmake
# ...

find_package(lunaris-encryption REQUIRED)

target_link_libraries(YourProjectName PRIVATE
    lunaris::lunaris-encryption
)
```

The find_package will try to find the `lunaris-encryption-config.cmake` or similar files that should be available to download in the Release tab.

## What's included

### ✅ Form32 & Form64 (Formula32 and Formula64)

```cpp
// The Form32 and Form64 look the same, but one uses uint32_t and the other uint64_t
Lunaris::Form32 fun32(5435); // random number here
Lunaris::Form64 fun64(9965); // random number here
```

Form**XX** are random-based "encryption" methods. This is within quotes because in security there's almost nothing. They shuffle randomly stuff based on a seed everytime you call `encode()` and do the opposite with `decode()`, like:

```cpp
Lunaris::Form64 funky(55); // put RANDOM on a real thing, not static number. This is an EXAMPLE!
const std::basic_string<unsigned char> str = (unsigned char*)"This is a fancy text to cryptograph. 0123456798! Yes!";
const auto enc = funky.encode(str.data(), str.length()); // std::vector<uint8_t>
const auto dec = funky.decode(enc.data(), enc.size()); // std::vector<uint8_t>
// dec should be == str here.
```
It is simple, but it has only a single key to encrypt/decrypt, so that's not really "awesome"

### ✅ RSA (32 bits) / RSACustom\<TYPE\>

RSA was a tough one to me. I had many issues with big numbers, trying to get the most performance with the best security possible. The maximum I got was 32 bits (default one is 32 bits).

With 32 bits I can do 64 bit math and I must keep primes at 16 bits. The numbers generated are all above 16 bits randomly based on the algorithm and their primes.

The RSA 32 bit algorithm works with 16-bit input to 32-bit output. Decrypt does the opposite, of course.

RSACustom is a version that allows your type to be the underlying type for operations. If you have a 128 bit unsigned type, RSA will be 64 bit, operations should work with 32 bit to 64 bit and so on.

From many sources[¹](http://www.muppetlabs.com/~breadbox/txt/rsa.html)[²](https://stackoverflow.com/questions/10005124/public-private-key-encryption-tutorials)[³](https://www.thecrazyprogrammer.com/2017/03/rsa-algorithm.html), I've come up with this simple and easy thing:

```cpp
const std::basic_string<unsigned char> str = (unsigned char*)"I can do stuff with RSA, yay!";
Lunaris::RSA fun;
fun.generate(); // or generate(number), but no number is random, so it's better for release.

Lunaris::RSADevice encrypt = fun.get_encrypt(); // YOU DO ENCRYPT WITH THIS ONE
Lunaris::RSADevice decrypt = fun.get_decrypt(); // THIS IS USED BY YOUR FRIEND ELSEWHERE!

// The other way to create the DECRYPT, using the public key:
const auto public_key = fun.get_combo(); // This is the public key combo, the one you give to them.
Lunaris::RSADevice manual_decrypt(public_key); // From get_combo() this is automatically assumed decrypt
// this should do the same as the decrypt declared before.

std::vector<uint8_t> encrypted_message = encrypt.transform(str.data(), str.size()); // there are other input types
std::vector<uint8_t> decrypted_message = decrypt.transform(encrypted_message); // should be the same as str now.
```

Custom is the same, but with \<type\> declaration.

### ✅ RSAPlus (32 bits RSA + Form64)

As the title suggest, this is a simple combo of both. Someone expecting for a simple RSA will think "what is happening in here?".

So, RSA works with 16-bit words, Form64 up to 64-bit, so this is a funky way to mess numbers around. They use the same random-generated key, so you still have only one `uint64_t` key! Isn't that awesome?

I added some shortcuts to make it even easier:

```cpp
const std::basic_string<unsigned char> str = (unsigned char*)"Fancy programming in here! I know unsigned char is not needed, but.";
auto enc = Lunaris::make_encrypt_auto(); // generates a random RSAPlus with key and everything!
auto dec = Lunaris::make_decrypt_auto(enc.get_public()); // with public key, make a decryptor that easy!
std::vector<uint8_t> ee, dd;

enc.transform(str.data(), str.length(), ee); // transform directly
dec.transform(ee.data(), ee.size(), dd); // do it back as easy as that
```

So probably you know why I did that to RSAPlus, the easier way, right? That's the way I think is the most secure between all of them. Have fun!

> And just probably don't try TableMatch, your RAM appreciate that.
