package SymmetricEncryption.DES

import SymmetricEncryption.Base64
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

fun main(args: Array<String>) {

    //1、要传输的文字和自有密钥（对于DES，长度为8位，前7位参与加密计算，最后一位作为校验码）
    val input = "input"
    val password = "password"

    //2、加密传输
    val encrypt = DESCrypt.encrypt(input, password)
    println("DES加密=" + encrypt)

    //3、解密传输过来文件
    val decrypt = DESCrypt.decrypt(encrypt, password)
    println("DES解密=" + String(decrypt))

}

object DESCrypt {

    //工作模式（根据具体情况选择）
    val transformation = "DES/CBC/PKCS5Padding"

    //算法
    val algorithm = "DES"

    //DES加密
    fun encrypt(input: String, password: String): String {

        //1、创建cipher对象
        val cipher = Cipher.getInstance(transformation)

        //2、初始化cipher
        val keyFactory = SecretKeyFactory.getInstance(algorithm)
        val desKeySpec = DESKeySpec(password.toByteArray())
        val key: Key = keyFactory.generateSecret(desKeySpec)
        val iv = IvParameterSpec(password.toByteArray())

        // CBC模式需要额外参数AlgorithmParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, key, iv)

        //3、加密
        val encrypt = cipher.doFinal(input.toByteArray())

        //4、base64编码
        return Base64.encode(encrypt)
    }

    //DES解密
    fun decrypt(input: String, password: String): ByteArray {

        //1、创建cipher对象
        val cipher = Cipher.getInstance(transformation)

        //2、初始化cipher(参数1：加密/解密模式)
        val keyFactory = SecretKeyFactory.getInstance(algorithm)
        val desKeySpec = DESKeySpec(password.toByteArray())
        val key: Key = keyFactory.generateSecret(desKeySpec)
        val iv = IvParameterSpec(password.toByteArray())

        // CBC模式需要额外参数AlgorithmParameterSpec
        cipher.init(Cipher.DECRYPT_MODE, key, iv)

        //3、Base64解密
        val decrypt = cipher.doFinal(Base64.decode(input))
        return decrypt
    }
}
