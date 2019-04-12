<?php
/**
 * Created by PhpStorm.
 * User: EDZ
 * Date: 2019/4/11
 * Time: 15:25
 */

namespace App\Services;


class Encryption
{
    /**
     * 加密密钥
     * @var string
     */
    private $key;


    /**
     * 加密算法
     * @var string
     */
    private $cipher;


    /**
     * 初始化加密密钥和加密方式
     * Encryption constructor.
     * @param $key
     * @param string $cipher
     */
    public function __construct($key, $cipher = 'AES-128-CBC')
    {
        $key = (string) base64_decode($key);

        if ($this->verifyRule($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            echo '密钥格式错误';
            exit;
        }
    }


    /**
     * 判断加密方式和传的key的长度是否相同
     * @param $key
     * @param $cipher
     * @return bool
     */
    private function verifyRule($key, $cipher)
    {
        // 按照8bit位的方式计算字符长度
        $length = mb_strlen($key, '8bit');

        //编码格式为AES128的要求字符长度为16。编码格式为AES256的要求字符长度为32位
        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }


    /**
     * 生成密钥
     * @param $cipher 加密方式
     * @return string
     * @throws \Exception
     */
    public static function generateKey($cipher)
    {
        // random_bytes生成一个加密安全的随机字节
        return base64_encode(random_bytes($cipher === 'AES-128-CBC' ? 16 : 32));
    }


    /**
     * 加密数据
     * @param $value
     * @param bool $serialize 是为了不管你传的是字符串还是数组，都能转成字符串
     * @return string
     * @throws \Exception
     */
    public function encrypt($value, $serialize = true)
    {
        // openssl_cipher_iv_length获取密码IV长度，$iv加解密的向量，有些方法需要设置比如CBC
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // 使用openssl_encrypt加密数据
        $value = \openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher, $this->key, 0, $iv
        );

        if ($value === false) {
            echo '该数据无法加密';
            exit;
        }

        // 生成签名，保证内容参数没有被更改
        $sign = $this->hash($iv = base64_encode($iv), $value);

        // 将IV，value,sign，生成数组并生成json数据
        $json = json_encode(compact('iv', 'value', 'sign'));

        if (json_last_error() !== JSON_ERROR_NONE) {
            echo '生成json数据失败';
            exit;
        }

        return base64_encode($json);
    }


    /**
     * 解密数据
     * @param $value
     * @param bool $unserialize
     * @return bool|mixed|string
     */
    public function decrypt($value, $unserialize = true)
    {
        $value = $this->getJsonValue($value);

        $iv = base64_decode($value['iv']);

        // 解密
        $decrypted = \openssl_decrypt(
            $value['value'], $this->cipher, $this->key, 0, $iv
        );

        if ($decrypted === false) {
            echo '无法解密该数据';
            exit;
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }


    /**
     * 使用hash_hmac生成sha256的加密值，用来验证参数是否更改。
     * @param $iv
     * @param $value
     * @return string
     */
    private function hash($iv, $value)
    {
        // 使用hash_hmac生成带有密钥的哈希值
        return hash_hmac('sha256', $iv.$value, $this->key);
    }


    /**
     * 获取json数据并验证完整性和数据真实性
     * @param $value
     * @return mixed
     */
    private function getJsonValue($value)
    {
        // 还原成数组
        $value = json_decode(base64_decode($value), true);

        if (! $this->validValue($value)) {
            echo '数据不完整';
            exit;
        }

        if (! $this->validSign($value)) {
            echo '签名无效';
            exit;
        }

        return $value;
    }


    /**
     * 验证数据完整性
     * @param $payload
     * @return bool
     */
    private function validValue($value)
    {
        return is_array($value) && isset($value['iv'], $value['value'], $value['sign']) &&
            strlen(base64_decode($value['iv'], true)) === openssl_cipher_iv_length($this->cipher);
    }


    /**
     * 验证签名
     * @param array $value
     * @return bool
     * @throws \Exception
     */
    private function validSign(array $value)
    {
        $calculated = $this->calculateSign($value, $bytes = random_bytes(16));

        // 比较2个签名是否相等
        return hash_equals(
            hash_hmac('sha256', $value['sign'], $bytes, true), $calculated
        );
    }


    /**
     * sha256 hash值是不可逆的
     * 拿随机字符串和值生成签名
     * @param $value
     * @param $bytes
     * @return string
     */
    private function calculateSign($value, $bytes)
    {
        return hash_hmac(
            'sha256', $this->hash($value['iv'], $value['value']), $bytes, true
        );
    }
}