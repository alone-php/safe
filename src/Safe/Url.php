<?php

namespace AlonePhp\Safe\Safe;

use Throwable;

trait Url {

    /**
     * @param mixed $data
     * @param array $mode
     * @return string
     */
    public static function urlEn(mixed $data, array $mode = ['aes', 'des', 'des3']): string {
        return static::urlEncrypt($data, function($safe) use ($mode) {
            return static::movEn($safe, $mode);
        });
    }

    /**
     * @param string $data
     * @return mixed
     */
    public static function urlDe(string $data): mixed {
        return static::urlDecrypt($data, function($safe) {
            return static::movDe($safe);
        });
    }

    /**
     * @param mixed $data
     * @param array $mode
     * @return string
     */
    public static function urlEns(mixed $data, array $mode = ['aes', 'des', 'des3']): string {
        return static::urlEncrypt($data, function($safe) use ($mode) {
            return static::movEns($safe, $mode);
        });
    }

    /**
     * @param string $data
     * @return mixed
     */
    public static function urlDes(string $data): mixed {
        return static::urlDecrypt($data, function($safe) {
            return static::movDes($safe);
        });
    }

    /**
     * @param mixed    $data
     * @param callable $callable
     * @return string
     */
    protected static function urlEncrypt(mixed $data, callable $callable): string {
        $safe = $callable($data);
        $json = json_encode($safe);
        $base = base64_encode($json);
        return str_replace(['+', '/', '='], ['-', '_', ''], $base);
    }

    /**
     * @param string   $data
     * @param callable $callable
     * @return mixed
     */
    protected static function urlDecrypt(string $data, callable $callable): mixed {
        try {
            if (!empty($data)
                && !empty($data = urldecode($data))
                && !empty($json = base64_decode(str_replace(['-', '_'], ['+', '/'], $data)))
                && !empty($safe = static::isJson($json))
                && !empty($string = $callable($safe))
            ) {
                $array = static::isJson($string);
                return !empty($array) ? $array : $string;
            }
            return [];
        } catch (Throwable $e) {
            return [];
        }
    }
}