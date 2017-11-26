package SymmetricEncryption.AES


import SymmetricEncryption.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * AES加密解密
 */

fun main(args: Array<String>) {

    //1、要传输的文字和自有密钥（对于AES，长度为16位）
    val input = "input"
    val password = "1234567812345678"

    //2、加密传输
    val encrypt = AESCrypt.encrypt(input, password)
    println("AES加密=" + encrypt)

    //3、解密传输过来的文件
    val decrypt = AESCrypt.decrypt(encrypt, password)
    println("AES解密=" + decrypt)

}

object AESCrypt {

    //算法
    val algorithm = "AES"

    //AES加密
    fun encrypt(input: String, password: String): String {

        //1.创建cipher对象
        val cipher = Cipher.getInstance(algorithm)

        //2.初始化cipher
        val keySpec = SecretKeySpec(password.toByteArray(), algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        //3.加密
        val encrypt = cipher.doFinal(input.toByteArray())
        val result = Base64.encode(encrypt)
        return result

    }

    //AES解密
    fun decrypt(input: String, password: String): String {

        //1、创建cipher对象
        val cipher = Cipher.getInstance(algorithm)

        //2、初始化cipher
        val keySpec = SecretKeySpec(password.toByteArray(), algorithm)
        cipher.init(Cipher.DECRYPT_MODE, keySpec)

        //3、解密
        val encrypt = cipher.doFinal(Base64.decode(input))
        val result = String(encrypt)
        return result
    }
}