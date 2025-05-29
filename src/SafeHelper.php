<?php

namespace AlonePhp\Safe;

use AlonePhp\Safe\Safe\Url;
use AlonePhp\Safe\Safe\AesDes;
use AlonePhp\Safe\Safe\Mov;
use AlonePhp\Safe\Safe\Openssl;

class SafeHelper {
    use Openssl;
    use AesDes;
    use Mov;
    use Url;

    /**
     * @param string $type //加密类型aes,des,des3
     * @param int    $length
     * @return static
     */
    public static function set(string $type, int $length = 0): static {
        return (new self($type, $length));
    }

    /**
     * aes加密
     * @param int $length
     * @return static
     */
    public static function aes(int $length = 128): static {
        return self::set('aes', $length);
    }

    /**
     * des加密
     * @return static
     */
    public static function des(): static {
        return self::set('des');
    }

    /**
     * des3加密
     * @return static
     */
    public static function des3(): static {
        return self::set('des3', 192);
    }

    /**
     * 设置加密类
     * @param bool $opt true=openssl,false=phpseclib3
     * @return $this
     */
    public function opt(bool $opt = false): static {
        $this->data['opt'] = $opt;
        return $this;
    }

    /**
     * 设置key和iv
     * @param string $key
     * @param string $iv
     * @return $this
     */
    public function setKeyIv(string $key, string $iv = ''): static {
        $this->data['key'] = $key;
        $this->data['iv'] = $iv;
        return $this;
    }

    /**
     * 加密使用phpseclib3
     * @param mixed $data
     * @param bool  $url
     * @param bool  $opt
     * @return array|string
     */
    public function encrypt(mixed $data, bool $url = false, bool $opt = false): array|string {
        return $this->opt($opt)->verify($data, true, $url);
    }

    /**
     * 加密使用openssl
     * @param mixed $data
     * @param bool  $url
     * @param bool  $opt
     * @return array|string
     */
    public function encrypts(mixed $data, bool $url = false, bool $opt = true): array|string {
        return $this->encrypt($data, $url, $opt);
    }

    /**
     * 解密使用phpseclib3
     * @param mixed $data
     * @param bool  $url
     * @param bool  $opt
     * @return array|string
     */
    public function decrypt(mixed $data, bool $url = false, bool $opt = false): array|string {
        return $this->opt($opt)->verify(base64_decode((!empty($url) ? urldecode($data) : $data)), false, $url);
    }

    /**
     * 解密使用openssl
     * @param mixed $data
     * @param bool  $url
     * @param bool  $opt
     * @return array|string
     */
    public function decrypts(mixed $data, bool $url = false, bool $opt = true): array|string {
        return $this->decrypt($data, $url, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function aesEncrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::aes()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 16 ? substr($key, 0, 16) : $key), (strlen($iv) > 16 ? substr($iv, 0, 16) : $iv))
            ->encrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function aesEncrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::aesEncrypt($data, $key, $iv, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function aesDecrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::aes()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 16 ? substr($key, 0, 16) : $key), (strlen($iv) > 16 ? substr($iv, 0, 16) : $iv))
            ->decrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function aesDecrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::aesDecrypt($data, $key, $iv, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function desEncrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::des()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 8 ? substr($key, 0, 8) : $key), (strlen($iv) > 8 ? substr($iv, 0, 8) : $iv))
            ->encrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function desEncrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::desEncrypt($data, $key, $iv, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function desDecrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::des()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 8 ? substr($key, 0, 8) : $key), (strlen($iv) > 8 ? substr($iv, 0, 8) : $iv))
            ->decrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function desDecrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::desDecrypt($data, $key, $iv, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function des3Encrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::des3()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 24 ? substr($key, 0, 24) : $key), (strlen($iv) > 8 ? substr($iv, 0, 8) : $iv))
            ->encrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function des3Encrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::des3Encrypt($data, $key, $iv, $opt);
    }

    /**
     * 使用phpseclib3
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function des3Decrypt(string $data, string $key, string $iv = '', bool $opt = false): string {
        $data = self::des3()
            ->opt($opt)
            ->setKeyIv((strlen($key) > 24 ? substr($key, 0, 24) : $key), (strlen($iv) > 8 ? substr($iv, 0, 8) : $iv))
            ->decrypt($data);
        return is_array($data) ? $data['msg'] : $data;
    }

    /**
     * 使用openssl
     * @param string $data
     * @param string $key
     * @param string $iv
     * @param bool   $opt
     * @return string
     */
    public static function des3Decrypts(string $data, string $key, string $iv = '', bool $opt = true): string {
        return self::des3Decrypt($data, $key, $iv, $opt);
    }


    /**
     * 判断字符串是否json,返回array
     * @param mixed     $json
     * @param bool|null $associative
     * @param int       $depth
     * @param int       $flags
     * @return mixed
     */
    public static function isJson(mixed $json, bool $associative = true, int $depth = 512, int $flags = 0): mixed {
        $json = json_decode((is_string($json) ? ($json ?: '') : ''), $associative, $depth, $flags);
        return (($json && is_object($json)) || (is_array($json) && $json)) ? $json : [];
    }

    /**
     * 通过a.b.c.d获取数组内容
     * @param array|null      $array   要取值的数组
     * @param string|null|int $key     支持aa.bb.cc.dd这样获取数组内容
     * @param mixed           $default 默认值
     * @param string          $symbol  自定符号
     * @return mixed
     */
    public static function getArr(array|null $array, string|null|int $key = null, mixed $default = null, string $symbol = '.'): mixed {
        if (isset($key)) {
            if (isset($array[$key])) {
                $array = $array[$key];
            } else {
                $symbol = $symbol ?: '.';
                $arr = explode($symbol, trim($key, $symbol));
                foreach ($arr as $v) {
                    if (isset($v) && isset($array[$v])) {
                        $array = $array[$v];
                    } else {
                        $array = $default;
                        break;
                    }
                }
            }
        }
        return $array ?? $default;
    }
}