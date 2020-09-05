package com.example.asymmetricencryption

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

@RestController
class RsaExample {

    private var PUBLIC_KEY_FILE: String = "Public.key"

    private var PRIVATE_KEY_FILE: String = "Private.key"

    @Throws(Exception::class)
    @GetMapping("/keys")
    fun keyGenerator() {


        println("------Generate Public and Private key--------")

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)

        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        val publicKey: PublicKey = keyPair.public

        val privateKey: PrivateKey = keyPair.private

        println("Pulling out parameters for making key pair ")

        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")

        val rsaPublicKeySpec: RSAPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec::class.java)
        val rsaPrivateKeySpec: RSAPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec::class.java)

        println("Saving public and private keys to files")

        val rsaObject = RsaExample()

        rsaObject.saveKeys(PUBLIC_KEY_FILE, rsaPublicKeySpec.modulus, rsaPublicKeySpec.publicExponent)
        rsaObject.saveKeys(PRIVATE_KEY_FILE, rsaPrivateKeySpec.modulus, rsaPrivateKeySpec.privateExponent)

        // ENCRYPTING DATA NOW using public key

        val encryptedData: ByteArray? = rsaObject.encryptData("hello kotlin programmer !")

        // Decrypting data using private key

        rsaObject.decryptData(encryptedData)


    }


    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class,
            InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    private fun decryptData(data: ByteArray?) {
        println("Decryption started")
        var decryptedData: ByteArray? = null

        val privateKey: PrivateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE)
        val cipher: Cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        decryptedData = cipher.doFinal(data)

        println("Decrypted data - " + decryptedData.toString())

        println("Decryption completed")


    }


    @Throws(IOException::class)
    private fun readPrivateKeyFromFile(fileName: String): PrivateKey {

        val fis: FileInputStream?
        val ois: ObjectInputStream?


        fis = FileInputStream(File(fileName))
        ois = ObjectInputStream(fis)
        val modulus: BigInteger = ois.readObject() as BigInteger
        val exponent: BigInteger = ois.readObject() as BigInteger

        // Get private key

        val rsaPrivateKeySpec: RSAPrivateKeySpec = RSAPrivateKeySpec(modulus, exponent)
        val fact: KeyFactory = KeyFactory.getInstance("RSA")
        val privateKey: PrivateKey = fact.generatePrivate(rsaPrivateKeySpec)

        return privateKey


    }


    private fun encryptData(data: String): ByteArray? {

        println("Encryption Started !")
        println("data before encrptyion - " + data)
        val dataToEncrypt: ByteArray = data.toByteArray()
        var encryptedData: ByteArray? = null
        try {
            val publicKey: PublicKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE)
            val cipher: Cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            encryptedData = cipher.doFinal(dataToEncrypt)


            println("Encrypted Data - " + encryptedData)


        } catch (e: Exception) {
            when (e) {
                is IOException, is NoSuchAlgorithmException, is NoSuchPaddingException,
                is InvalidKeyException, is IllegalBlockSizeException, is BadPaddingException -> {
                    e.printStackTrace()
                }
                else -> throw e
            }
        }



        println("Encrpytion completed")
        return encryptedData
    }


    @Throws(IOException::class, ClassNotFoundException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun readPublicKeyFromFile(fileName: String): PublicKey {

        var fis: FileInputStream? = null
        var ois: ObjectInputStream? = null
        fis = FileInputStream(File(fileName))
        ois = ObjectInputStream(fis)
        val modulus: BigInteger = ois.readObject() as BigInteger
        val exponent: BigInteger = ois.readObject() as BigInteger

        // Get public key

        val rsaPublicKeySpec: RSAPublicKeySpec = RSAPublicKeySpec(modulus, exponent)
        val fact: KeyFactory = KeyFactory.getInstance("RSA")
        val publicKey: PublicKey = fact.generatePublic(rsaPublicKeySpec)
        return publicKey


    }

    private fun saveKeys(fileName: String, modulus: BigInteger?, exp: BigInteger?) {

        var fos: FileOutputStream? = null
        var oos: ObjectOutputStream? = null

        try {
            println("Generating" + fileName + ".....")

            fos = FileOutputStream(fileName)
            oos = ObjectOutputStream(BufferedOutputStream(fos))
            oos.writeObject(modulus)
            oos.writeObject(exp)

            println(fileName + "Generated successully")
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {

            if (oos != null) {
                oos.close()
                if (fos != null) {
                    fos.close()
                }
            }

        }


    }

}