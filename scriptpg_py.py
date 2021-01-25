import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

# we can start by generating a primary key. For this example, we'll use RSA, but it could be DSA or ECDSA as well
key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

# we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
uid = pgpy.PGPUID.new('manthos stavrou', comment='PGP CRYPTO', email='manthos@yahoo.com')

# now we must add the new user id to the key. We'll need to specify all of our preferences at this point
# because PGPy doesn't have any built-in key preference defaults at this time
# this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
            
            
            
# assuming we already have a primary key, we can generate a new key and add it as a subkey thusly:
subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

# preferences that are specific to the subkey can be chosen here
# any preference(s) needed for actions by this subkey that not specified here
# will seamlessly "inherit" from those specified on the selected User ID
key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

# ASCII armored
keystr = str(key)

print(keystr)


KEY_PRIV = keystr.lstrip()

priv_key = pgpy.PGPKey()
priv_key.parse(KEY_PRIV)
pass

pub_key = key.pubkey
pass
#------------------

with open("encrypted.csv", "r") as csv_file:
    SOME_TEXT = csv_file.read()

msg = pgpy.PGPMessage.new(SOME_TEXT)

# this returns a new PGPMessage that contains an encrypted form of the
# unencrypted message
encrypted_message = pub_key.encrypt(msg)

pgpstr = str(encrypted_message)

with open("encryption", "w") as text_file:
    text_file.write(pgpstr)

print(pgpstr)
print("Encryption Complete")

message_from_file = pgpy.PGPMessage.from_file("encryption")

raw_message = priv_key.decrypt(message_from_file).message
 
with open("Descrypted_File.csv","w") as csv_file:
    csv_file.write(raw_message)

print(raw_message)
print("Decryption Complete")
