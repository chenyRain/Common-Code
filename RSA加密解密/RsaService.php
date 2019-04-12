<?php
/**
 * Created by PhpStorm.
 * User: EDZ
 * Date: 2019/4/12
 * Time: 15:19
 */

namespace App\Services;


class RsaService
{
    /**
     * 公钥
     * @var
     */
    protected $public_key;


    /**
     * 私钥
     * @var
     */
    protected $private_key;


    /**
     * 公钥文件路径
     * @var
     */
    protected $public_key_path = 'keys/rsa_public_key.pub';


    /**
     * 采用pkcs8只是为了方便程序解析
     * 私钥文件路径
     * @var
     */
    protected $private_key_path = 'keys/rsa_private_key_pkcs8.pem';


    /**
     * 初始化配置
     * RsaService constructor.
     * @param bool $type 默认私钥加密
     */
    public function __construct($type = true)
    {
        if ($type) {
            $this->private_key = $this->getPrivateKey();
        } else {
            $this->public_key = $this->getPublicKey();
        }
    }


    /**
     * 配置私钥
     * openssl_pkey_get_private这个函数可用来判断私钥是否是可用的，可用，返回资源
     * @return bool|resource
     */
    private function getPrivateKey()
    {
        $original_private_key = file_get_contents(__DIR__ . '/../' . $this->private_key_path);
        return openssl_pkey_get_private($original_private_key);
    }


    /**
     * 配置公钥
     * openssl_pkey_get_public这个函数可用来判断私钥是否是可用的，可用，返回资源
     * @return resource
     */
    public function getPublicKey()
    {
        $original_public_key = file_get_contents(__DIR__ . '/../' . $this->public_key_path);
        return openssl_pkey_get_public($original_public_key);
    }


    /**
     * 私钥加密
     * @param $data
     * @param bool $serialize 是为了不管你传的是字符串还是数组，都能转成字符串
     * @return string
     * @throws \Exception
     */
    public function privateEncrypt($data, $serialize = true)
    {
        openssl_private_encrypt(
            $serialize ? serialize($data) : $data,
            $encrypted, $this->private_key
        );

        if ($encrypted === false) {
            throw new \Exception('Could not encrypt the data.');
        }

        return base64_encode($encrypted);
    }


    /**
     * 私钥解密
     * @param $data
     * @param bool $unserialize
     * @return mixed
     * @throws \Exception
     */
    public function privateDecrypt($data, $unserialize = true)
    {
        openssl_private_decrypt(base64_decode($data),$decrypted, $this->private_key);

        if ($decrypted === false) {
            throw new \Exception('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }


    /**
     * 公钥加密
     * @param $data
     * @param bool $serialize 是为了不管你传的是字符串还是数组，都能转成字符串
     * @return string
     * @throws \Exception
     */
    public function publicEncrypt($data, $serialize = true)
    {
        openssl_public_encrypt(
            $serialize ? serialize($data) : $data,
            $encrypted, $this->public_key
        );

        if ($encrypted === false) {
            throw new \Exception('Could not encrypt the data.');
        }

        return base64_encode($encrypted);
    }


    /**
     * 公钥解密
     * @param $data
     * @param bool $unserialize
     * @return mixed
     * @throws \Exception
     */
    public function publicDecrypt($data, $unserialize = true)
    {
        openssl_public_decrypt(base64_decode($data),$decrypted, $this->public_key);

        if ($decrypted === false) {
            throw new \Exception('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }
}